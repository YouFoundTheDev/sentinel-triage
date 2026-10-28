# Contributing

This is a portfolio/reference project, but issues and pull requests are welcome.

## Setup

```bash
cp .env.example .env
# set GOOGLE_CLOUD_PROJECT and authenticate with ADC
gcloud auth application-default login
make install
```

## Checks

```bash
make lint
make test
```

`make lint` runs Ruff; `make test` runs pytest. CI also checks formatting with
`ruff format --check .`. The live eval (`make eval`) calls Vertex AI and may incur cost;
run it only when you intend to update `docs/eval.md`.

## Pull requests

- Keep changes small and focused.
- Do not add secrets, credentials, or `.env` files.
- Add or update tests for behavior changes.
- Update `docs/eval.md` only with results from an actual run; never invent metrics.
- Update `README.md` or `infra/README.md` when commands, IAM, or endpoints change.
- Preserve the security properties: no URL fetching, parameterized BigQuery, validated
  RDAP redirects, fail-closed escalation, and least-privilege service accounts.

## Code style

Simple, readable Python with typed signatures and pydantic models at boundaries. Avoid
unused abstractions. The UI is intentionally vanilla HTML/CSS/JS with no build step.
