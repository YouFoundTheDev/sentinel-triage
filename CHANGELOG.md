# Changelog

## 0.1.0 — 2026-10-29

Initial portfolio release.

- Data pipeline for OpenPhish + Tranco into BigQuery `triage.indicators`.
- BigQuery sighting lookup, DNS/RDAP enrichment, URL feature extraction, and BQML scoring
  tools with mocked network tests.
- ADK investigator + structured verdict formatter on Gemini via Vertex AI.
- Deterministic fail-closed policy and JSON run logging.
- FastAPI `/triage`, `/healthz`/`/health`, `/readyz`/`/ready`.
- Private Cloud Run deployment with a least-privilege runtime service account.
- Cloud Build CI/CD trigger on `main`; GitHub Actions lint/test on pull requests.
- BigQuery ML logistic-regression URL classifier and `ml_score` tool.
- Vanilla HTML/CSS/JS triage console at `/ui/`.
- Honest 20-case eval baseline and a quota-limited 12-case with/without-ML comparison.

Known limitations: the full with-ML eval is pending, Cloud Run reserves `/healthz`, and
RDAP can return 403 from Cloud Run egress. See the README and `docs/eval.md`.
