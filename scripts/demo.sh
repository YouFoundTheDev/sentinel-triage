#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-wide-factor-387115}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-soc-triage-agent}"

URL=$(gcloud run services describe "$SERVICE" \
  --region="$REGION" \
  --project="$PROJECT_ID" \
  --format='value(status.url)')
TOKEN=$(gcloud auth print-identity-token)

auth=(-H "Authorization: Bearer ${TOKEN}")

echo "== health =="
curl -sS "${auth[@]}" "$URL/health"
echo
echo "== ready =="
curl -sS "${auth[@]}" "$URL/ready"
echo

for indicator in "https://example.com/" "http://alibabaglobalnetwork.com/"; do
  echo "== triage ${indicator} =="
  curl -sS -X POST "$URL/triage" \
    "${auth[@]}" \
    -H 'Content-Type: application/json' \
    -d "{\"indicator\":\"${indicator}\"}" \
    --max-time 300 \
    | jq '{run_id, verdict, tools: [.tools_called[] | {tool, status, summary}], latency_ms, error}'
done
