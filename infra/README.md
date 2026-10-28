# Infrastructure

Stage 4 creates a private Cloud Run service backed by BigQuery and Vertex AI.

## Resources created

| Resource | Value |
|---|---|
| Project | `wide-factor-387115` |
| Region | `us-central1` |
| BigQuery dataset | `triage` (US) |
| BigQuery table | `triage.indicators` |
| Artifact Registry repo | `soc-triage` (`us-central1`, Docker) |
| Runtime service account | `soc-triage-runtime@wide-factor-387115.iam.gserviceaccount.com` |
| Builder service account | `soc-triage-builder@wide-factor-387115.iam.gserviceaccount.com` |
| Cloud Run service | `soc-triage-agent` |
| Cloud Run URL | `https://soc-triage-agent-dqd5vawjva-uc.a.run.app` |
| Ingress | authenticated invocations only |

`setup.sh` enables Vertex AI, BigQuery, Cloud Run, Artifact Registry, Cloud Build, and IAM.
The dataset was created while billing was disabled, so setup also removes the BigQuery
sandbox 60-day table/dataset expirations.

## IAM: runtime service account

| Role / access | Scope | Why |
|---|---|---|
| Dataset `READER` ACL | dataset `triage` | Read the indicator table |
| `roles/bigquery.jobUser` | project | Run query jobs (`bigquery.jobs.create`) |
| `roles/aiplatform.user` | project | Call Gemini via Vertex AI |

Dataset-level IAM binding through `bq add-iam-policy-binding -d` is allowlisted in this
project and failed with "This feature requires allowlisting." `infra/grant_dataset_read.py`
grants the equivalent legacy `READER` dataset ACL, scoped only to `triage`; no project-wide
BigQuery data role is used.

`roles/bigquery.dataViewer` on a dataset would not include job creation anyway, so
`roles/bigquery.jobUser` is required. The service account has no `roles/run.invoker` (Cloud
Run IAM authenticates the caller, not the service) and no Artifact Registry role (the Cloud
Run service agent pulls the image).

## Run setup

Run `make data` first so the `triage.indicators` table exists. Then:

```bash
./infra/setup.sh
```

The key commands are:

```bash
PROJECT_ID=wide-factor-387115
REGION=us-central1
RUNTIME_SA=soc-triage-runtime@${PROJECT_ID}.iam.gserviceaccount.com

gcloud services enable \
  aiplatform.googleapis.com bigquery.googleapis.com run.googleapis.com \
  artifactregistry.googleapis.com cloudbuild.googleapis.com iam.googleapis.com \
  --project "$PROJECT_ID"

gcloud iam service-accounts create soc-triage-runtime \
  --display-name="SOC triage runtime" --project "$PROJECT_ID"

PROJECT_ID="$PROJECT_ID" BQ_DATASET=triage RUNTIME_SA="$RUNTIME_SA" \
  uv run python infra/grant_dataset_read.py

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role="roles/bigquery.jobUser" --condition=None

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role="roles/aiplatform.user" --condition=None

gcloud artifacts repositories create soc-triage \
  --repository-format=docker --location="$REGION" \
  --description="SOC triage agent images" --project "$PROJECT_ID"
```

## Deploy

```bash
./infra/deploy.sh
```

This uses Cloud Build to build the Dockerfile (no local Docker daemon is required), pushes
`us-central1-docker.pkg.dev/wide-factor-387115/soc-triage/agent:latest`, and deploys the
private Cloud Run service with:

- `--no-allow-unauthenticated`
- runtime service account `soc-triage-runtime`
- `--min-instances=0 --max-instances=2 --concurrency=4 --timeout=240`
- env vars for project, Vertex location `global`, model, and BigQuery table

For a new image tag:

```bash
TAG="$(git rev-parse --short HEAD)" ./infra/deploy.sh
```

## CI/CD

Create the builder identity:

```bash
./infra/ci_setup.sh
```

| Role / access | Scope | Why |
|---|---|---|
| `roles/cloudbuild.builds.builder` | project | Build logs, workspace storage, Artifact Registry upload |
| `roles/run.admin` | project | Deploy the Cloud Run service |
| `roles/iam.serviceAccountUser` | runtime SA only | Deploy as `soc-triage-runtime` |

`cloudbuild.yaml` runs lint/tests, builds, pushes, then deploys. Lint or test failures stop
the pipeline before build/deploy. It uses Cloud Logging only because a user-specified build
service account is used.

Manual end-to-end verification:

```bash
gcloud builds submit --config=cloudbuild.yaml \
  --service-account=projects/wide-factor-387115/serviceAccounts/soc-triage-builder@wide-factor-387115.iam.gserviceaccount.com \
  --substitutions=SHORT_SHA=manual-$(date +%s) \
  --project=wide-factor-387115 .
```

Verified build: `0092d224-2e61-4c5a-acf1-6770c37dd7cd` — all four steps `SUCCESS`; revision
`soc-triage-agent-00003-fjh`; image tag `ci-1793205942`.

### Push trigger

The private repository is `YouFoundTheDev/sentinel-triage`. The connection
`soc-triage-github` exists in `us-central1` and is waiting for OAuth authorization and the
Cloud Build GitHub App installation. `ci_setup.sh` enables Secret Manager and grants the
Cloud Build service agent the Secret Manager access needed for the OAuth token.

Create/authorize the connection:

```bash
gcloud builds connections create github soc-triage-github \
  --region=us-central1 --project=wide-factor-387115
# Open the printed OAuth link, authorize, then install the Cloud Build GitHub App
# on the private sentinel-triage repository.
gcloud builds connections describe soc-triage-github \
  --region=us-central1 --project=wide-factor-387115
```

Then link the repository and create the trigger:

```bash
gcloud builds repositories create sentinel-triage \
  --connection=soc-triage-github \
  --region=us-central1 \
  --remote-uri=https://github.com/YouFoundTheDev/sentinel-triage.git \
  --project=wide-factor-387115

GITHUB_OWNER=YouFoundTheDev \
GITHUB_REPO=sentinel-triage \
CONNECTION=soc-triage-github \
./infra/create_trigger.sh
```

Equivalent 2nd-gen command:

```bash
gcloud builds triggers create github \
  --name=soc-triage-main \
  --repository=projects/wide-factor-387115/locations/us-central1/connections/CONNECTION/repositories/REPO \
  --branch-pattern='^main$' \
  --build-config=cloudbuild.yaml \
  --service-account=projects/wide-factor-387115/serviceAccounts/soc-triage-builder@wide-factor-387115.iam.gserviceaccount.com \
  --region=us-central1 \
  --project=wide-factor-387115
```

For a 1st-gen GitHub App connection, use `--repo-owner` and `--repo-name` instead of
`--repository`, and omit `--region`.

The repository is pushed, but the trigger is not created yet because the GitHub OAuth/app
installation step requires browser authorization. The pipeline itself is verified manually.

### Pull-request checks

`.github/workflows/ci.yml` runs `uv sync`, `ruff check`, and `pytest` on pull requests to
`main`. It uses no GCP credentials and does not deploy.

## Health endpoint caveat

Cloud Run's edge reserves some URL paths, including paths ending in `z` such as
`/healthz` (see the Cloud Run known issues). `/healthz` and `/readyz` are implemented in
the app and work locally and inside the container, but `/healthz` does not reach the
container on a `run.app` URL and returns a Google-branded 404.

The app therefore also exposes `/health` and `/ready`. Use those on Cloud Run. Serving the
exact external path `/healthz` would require a load balancer or hosting rewrite, which is
not included to avoid extra cost.

## Verify

Unauthenticated requests are rejected (use a non-reserved path):

```bash
URL=$(gcloud run services describe soc-triage-agent \
  --region=us-central1 --project=wide-factor-387115 \
  --format='value(status.url)')

curl -i "$URL/ready"            # HTTP 403
```

Use your Google identity to invoke:

```bash
TOKEN=$(gcloud auth print-identity-token)

curl -s -H "Authorization: Bearer $TOKEN" "$URL/health"
curl -s -H "Authorization: Bearer $TOKEN" "$URL/ready"

curl -s -X POST "$URL/triage" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"indicator":"https://example.com/"}' | jq
```

Verified on the deployed revision: `/ready` returned 200 with
`{"status":"ready","checks":{"config":"ok","bigquery":"ok"}}`, and `/triage` returned 200
for `https://example.com/`. The first request took about 57 seconds including cold start.

`/ready` checks configuration and BigQuery dataset access without a model call. A live
`/triage` request is the real Vertex AI permission check.

Optional: grant another user or group permission to invoke:

```bash
gcloud run services add-iam-policy-binding soc-triage-agent \
  --region=us-central1 --project=wide-factor-387115 \
  --member="user:analyst@example.com" \
  --role="roles/run.invoker"
```

## Cost and security notes

- Cloud Run scales to zero; max instances is 2 to cap accidental spend.
- No secrets are stored in the repo or container image. Cloud Run uses the runtime
  service account through the metadata server; local runs use ADC.
- The API does not parse bearer tokens; Cloud Run IAM validates them before the request
  reaches the container.
- The container runs as UID 10001, not root.
- Some RDAP registries returned HTTP 403 from Cloud Run egress during verification. The
  enrichment tool correctly returns `partial`/`unavailable` in that case, and the policy
  escalates instead of auto-closing.
- The builder account has no project-wide `iam.serviceAccountUser`; it can act only as the
  runtime service account. It has no BigQuery or Vertex AI roles because tests are mocked
  and deployment does not call those APIs.
