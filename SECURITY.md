# Security Policy

## Supported versions

`0.1.x` is the current portfolio release. There is no long-term support commitment.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem. Use GitHub's private
vulnerability reporting for this repository:

<https://github.com/YouFoundTheDev/sentinel-triage/security/advisories/new>

Include the affected version/commit, reproduction steps, impact, and any suggested fix.
You can expect an acknowledgement and a triage decision, but this is a portfolio project,
not a production service with an SLA.

## Security design

- Cloud Run is deployed with `--no-allow-unauthenticated`; callers need an identity token
  with `roles/run.invoker`.
- The runtime service account has only dataset `READER`, `roles/bigquery.jobUser`, and
  `roles/aiplatform.user`.
- The agent never fetches or connects to the submitted URL. It performs DNS queries,
  validated RDAP lookups, BigQuery queries, and Vertex AI calls.
- BigQuery queries are parameterized. The lookup table reference is validated before
  interpolation.
- RDAP redirects are limited to HTTPS/public hosts, and redirect chains are capped.
- No application secrets are stored in the repo or image. Local development uses
  Application Default Credentials. Cloud Run uses the runtime service account.
- The container runs as non-root UID 10001.
- The frontend uses `textContent` for all API-provided strings and has no external script,
  font, or CDN dependencies.

## Out of scope

This project is not a production SOC product. It has no tenant isolation, application-level
authorization, rate limiting, audit retention policy, or incident-response SLA. Do not send
real credentials, customer data, or live incident details to the demo service.
