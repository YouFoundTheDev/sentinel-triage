# Demo

The fastest demo is:

```bash
gcloud auth login
./scripts/demo.sh
```

The script resolves the private Cloud Run URL, gets an identity token, calls `/health` and
`/ready`, then submits two indicators. The service is not public: requests without a token
get 403.

Manual version:

```bash
URL=$(gcloud run services describe soc-triage-agent \
  --region=us-central1 --project=wide-factor-387115 \
  --format='value(status.url)')
TOKEN=$(gcloud auth print-identity-token)

curl -s -H "Authorization: Bearer $TOKEN" "$URL/health"
curl -s -H "Authorization: Bearer $TOKEN" "$URL/ready"

curl -s -X POST "$URL/triage" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"indicator":"https://example.com/"}' | jq

curl -s -X POST "$URL/triage" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"indicator":"http://alibabaglobalnetwork.com/"}' | jq
```

## Actual output

Abridged from a run against revision `soc-triage-agent-00008-9j9`. Timings include cold
start and varied by request. The two results are `needs_review` because RDAP returned HTTP
403 from Cloud Run egress; that is the expected fail-closed behavior.

### Health and readiness

```json
{"status":"ok"}
{"status":"ready","checks":{"config":"ok","bigquery":"ok"}}
```

### Benign example

Input: `https://example.com/`

```json
{
  "run_id": "c59bb6dc01624b9592a7df408aad205d",
  "verdict": {
    "severity": "info",
    "confidence": 0.85,
    "recommended_action": "close as benign",
    "status": "needs_review",
    "classification": "benign"
  },
  "tools": [
    {"tool": "lookup_indicator", "status": "ok",
     "summary": "Found 1 sighting(s) for example.com: 0 malicious, 1 benign."},
    {"tool": "enrich_domain", "status": "partial",
     "summary": "DNS ok (A=2, MX=0, NS=2); RDAP unavailable."},
    {"tool": "extract_url_features", "status": "ok",
     "summary": "URL length 20, 0 subdomain(s), suspicious TLD=False, IP host=False, hostname entropy=3.10."},
    {"tool": "ml_score", "status": "ok",
     "summary": "ML model predicts benign (malicious probability 0.031)."}
  ],
  "latency_ms": 39028.07,
  "error": null
}
```

The model wanted to auto-close as benign, but the policy escalated because DNS/RDAP
enrichment was partial. Submitting the URL did not fetch it; only DNS, RDAP, BigQuery, and
Vertex AI were used.

### Malicious example

Input: `http://alibabaglobalnetwork.com/`

```json
{
  "run_id": "5b65c7d6e461457087438e9c0e3a63c6",
  "verdict": {
    "severity": "high",
    "confidence": 0.88,
    "recommended_action": "Block at the proxy/DNS and escalate to Tier 2 for phishing incident investigation.",
    "status": "needs_review",
    "classification": "malicious"
  },
  "tools": [
    {"tool": "lookup_indicator", "status": "ok",
     "summary": "Found 1 sighting(s) for alibabaglobalnetwork.com: 1 malicious, 0 benign."},
    {"tool": "enrich_domain", "status": "partial",
     "summary": "DNS ok (A=2, MX=1, NS=2); RDAP unavailable."},
    {"tool": "extract_url_features", "status": "ok",
     "summary": "URL length 32, 0 subdomain(s), suspicious TLD=False, IP host=False, hostname entropy=3.66."},
    {"tool": "ml_score", "status": "ok",
     "summary": "ML model predicts malicious (malicious probability 0.998)."}
  ],
  "latency_ms": 14466.67,
  "error": null
}
```

The direct OpenPhish sighting and ML score agree. The policy still sends malicious verdicts
to human review; it never auto-closes them.

## Notes

- Use `/health` and `/ready` on Cloud Run. The edge reserves `/healthz`, even though the
  app implements it for local/container use.
- A 429 or model timeout is returned as a fail-closed `needs_review` result by the agent;
  the HTTP endpoint returns 503/504 only for unexpected API-level failures.
- The ML tool is enabled by default. The eval comparison showed it did not improve the
  quota-limited subset; see [`eval.md`](eval.md).
