# SOC Alert Triage Agent on GCP

Given a suspicious URL or domain, this project gathers context, returns a structured
verdict (severity, confidence, reasoning, evidence, recommended action), and escalates
uncertain results for human review instead of auto-closing them.

> **Status: Stage 5 — data pipeline, tools, ADK triage agent, deterministic policy, eval,
> FastAPI, private Cloud Run deployment, Cloud Build pipeline, and PR checks.** BigQuery ML
> and the final README/demo land in later stages.

## What Stage 1 does

- Downloads the public [OpenPhish](https://openphish.com/) URL feed and a sample of
  benign domains from [Tranco](https://tranco-list.eu/).
- Normalizes URLs/domains, drops fragments and default ports, and rejects URL
  credentials, private/internal hosts, and malformed indicators.
- Deduplicates rows while preserving cross-label conflicts (the same domain seen as
  both malicious and benign), because the agent must escalate conflicting evidence.
- Loads the result into BigQuery as `triage.indicators` (`url`, `domain`, `label`,
  `threat_type`, `first_seen`, `source`).
- Caps the load at 5,000 malicious and 5,000 benign rows by default. OpenPhish currently
  supplies about 300 URLs; Tranco supplies the benign sample.
- Writes a local JSONL snapshot and run statistics, so the pipeline can be exercised
  without GCP.

### Data caveats

- OpenPhish does not publish a per-URL first-seen timestamp, so `first_seen` is `NULL`
  for that source. `threat_type` is `phishing`.
- Tranco is a popularity ranking, not a verified benign list.
- URLhaus's unauthenticated CSV export now returns HTTP 410; its current exports require
  a free abuse.ch Auth-Key, so this stage does not use URLhaus.
- `make data` truncates and replaces the `indicators` table to keep runs idempotent.

## Tools (Stage 2)

All tools return pydantic-defined JSON envelopes. Lookup and enrichment failures are
returned as structured `partial` or `unavailable` results, never raised.

- `lookup_indicator(domain_or_url)` — parameterized BigQuery query for previous
  malicious/benign sightings. Reports conflicting labels explicitly.
- `enrich_domain(domain)` — A/MX/NS DNS records plus RDAP registration date, registrar,
  nameservers, and age. DNS and HTTP calls have timeouts. RDAP redirects are limited and
  validated to HTTPS/public hosts.
- `extract_url_features(url)` — local-only features: URL/host lengths, subdomain count,
  digit ratio, suspicious TLD, IP-literal host, punycode, query/path shape, suspicious
  keywords, and Shannon entropy.

None of these tools fetches or connects to the submitted URL. `lookup_indicator` talks
only to BigQuery; `enrich_domain` talks only to DNS and a fixed RDAP bootstrap endpoint.

## Agent (Stage 3)

The ADK pipeline uses two Gemini 3.8 Flash agents:

1. **Investigator** — has the three tools, calls each once, and returns an evidence summary.
2. **Verdict formatter** — has no tools and uses `output_schema=Verdict` to produce the
   structured result reliably.

Splitting the tool-calling and formatting steps avoids the ADK structured-output-plus-tools
fallback, which looped during testing. The deterministic policy then runs in code, replacing
model-provided evidence with actual tool records and forcing `needs_review` when confidence
is below 0.7, any tool is partial/unavailable/invalid, required tools are missing, lookup
evidence conflicts, the classification is unknown, or the verdict is malicious/high severity.
Only confident benign results can auto-close.

Every run emits one JSON log line with the input, tools called, verdict, policy escalations,
and latency. See `docs/eval.md` for the 20-case eval; it is a small single run, not a
production benchmark.

## API (Stage 4)

FastAPI exposes the agent:

- `POST /triage` — body `{"indicator": "https://example.com/"}`; returns `TriageResult`
  with the structured verdict, tool calls, policy escalations, and latency.
- `GET /healthz` — liveness only; no Google Cloud access.
- `GET /readyz` — config and BigQuery dataset access; no model call.
- `GET /health` and `GET /ready` — Cloud Run-safe aliases (see below).

Run locally:

```bash
make api
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/readyz
curl -s -X POST http://127.0.0.1:8080/triage \
  -H 'Content-Type: application/json' \
  -d '{"indicator":"https://example.com/"}'
```

The container runs as a non-root user. Cloud Run is private and accepts only authenticated
invocations. See `infra/README.md` for exact setup/deploy commands and IAM rationale.

Cloud Run's edge reserves some paths ending in `z`, including `/healthz`; requests to
`/healthz` on a `run.app` URL are answered by Google with 404 before reaching the container.
The app implements `/healthz`/`/readyz` and also `/health`/`/ready`; use the non-`z` aliases
on Cloud Run. Serving exact `/healthz` externally would require a load balancer or hosting
rewrite.

## CI/CD (Stage 5)

`cloudbuild.yaml` runs sequentially:

1. install uv, sync dependencies, `ruff check`, `pytest`
2. build the Docker image
3. push it to Artifact Registry tagged with `$SHORT_SHA`
4. deploy to Cloud Run

A failure in lint or tests stops the pipeline before build/deploy. The build uses the
dedicated `soc-triage-builder` service account:
`roles/cloudbuild.builds.builder`, `roles/run.admin`, and `roles/iam.serviceAccountUser`
only on `soc-triage-runtime`. `infra/ci_setup.sh` creates and grants it.

The manual pipeline was verified end to end (all four Cloud Build steps `SUCCESS`), and the
new revision served `/health` and `/ready` with 200.

The private repository is `https://github.com/YouFoundTheDev/sentinel-triage`. The Cloud
Build GitHub connection `soc-triage-github` is complete, and the
`soc-triage-main` trigger runs this pipeline on every push to `main`. The trigger uses the
dedicated `soc-triage-builder` service account. A push-triggered build and the GitHub
Actions workflow were both verified successfully. Exact setup commands are in
`infra/README.md`.

Pull requests run lint + tests in `.github/workflows/ci.yml` using GitHub Actions and no GCP
credentials.

## Prerequisites

- Python 3.11+ (uv uses the version in `.python-version`, currently 3.13)
- [uv](https://docs.astral.sh/uv/)
- A Google Cloud project with billing enabled, for the BigQuery load
- gcloud CLI and Application Default Credentials
- Docker (later stages)

## Setup

```bash
cp .env.example .env
# Edit .env and set GOOGLE_CLOUD_PROJECT to your project ID.
gcloud auth application-default login
make install
```

`GOOGLE_CLOUD_LOCATION=global` is intentional for `gemini-3.8-flash`, which is available
on the `global`, `us`, and `eu` endpoints rather than `us-central1`. The model is not used
until Stage 3.

## Run and verify

```bash
make data-local   # download + clean only; no GCP calls
make data         # download + clean + load BigQuery
make test
make lint
make eval         # live Vertex AI eval; writes docs/eval.md
make setup        # create service account, IAM, Artifact Registry
make deploy       # build/push image and deploy private Cloud Run service
```

Check the loaded data:

```bash
bq query --use_legacy_sql=false \
  'SELECT label, source, COUNT(*) AS record_count
   FROM `YOUR_PROJECT.triage.indicators`
   GROUP BY label, source
   ORDER BY label, source'
```

Expected shape: `openphish`/`malicious` and `tranco`/`benign` groups, with benign rows
capped at the configured limit.

## Layout

```text
agent/      ADK investigator, formatter, policy, and JSON logging
api/        FastAPI service
data/       download, clean, and BigQuery load
tools/      BigQuery lookup, DNS/RDAP enrichment, URL features
tests/      unit tests and fixtures
infra/      GCP setup, deploy, and CI/CD helper scripts
.github/    Pull-request lint/test workflow
evals/      labeled eval set and runner (Stage 3)
docs/       eval report and demo notes
scripts/    demo commands (Stage 7)
```

## Security and configuration

- No credentials or secrets are stored in the repository. `.env` is git-ignored.
- Local BigQuery/Vertex access uses Application Default Credentials.
- The cleaning step performs no DNS or network lookups; it only parses text and rejects
  private/internal hosts.
- The agent will never fetch the submitted URL itself. That constraint is enforced when
  the tools are added in Stage 2.

## Next stages

1. BigQuery ML bonus and a with/without-ML eval comparison.
2. Full README, architecture diagram, and demo.

The full write-up and architecture diagram will be added in Stage 7.
