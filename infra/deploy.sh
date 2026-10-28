#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-wide-factor-387115}"
REGION="${REGION:-us-central1}"
AR_REPO="${AR_REPO:-soc-triage}"
RUNTIME_SA_NAME="${RUNTIME_SA_NAME:-soc-triage-runtime}"
RUNTIME_SA="${RUNTIME_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
SERVICE="${SERVICE:-soc-triage-agent}"
TAG="${TAG:-latest}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/agent:${TAG}"

# Cloud Build builds the Dockerfile; no local Docker daemon is required.
gcloud builds submit --tag="$IMAGE" --project="$PROJECT_ID" --timeout=1200s .

gcloud run deploy "$SERVICE" \
  --image="$IMAGE" \
  --region="$REGION" \
  --project="$PROJECT_ID" \
  --service-account="$RUNTIME_SA" \
  --no-allow-unauthenticated \
  --cpu=1 \
  --memory=1Gi \
  --min-instances=0 \
  --max-instances=2 \
  --concurrency=4 \
  --timeout=240 \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=global,GOOGLE_GENAI_USE_ENTERPRISE=TRUE,GEMINI_MODEL=gemini-3.8-flash,BQ_DATASET=${BQ_DATASET:-triage},BQ_TABLE=${BQ_TABLE:-indicators},BQ_LOCATION=US,LOG_LEVEL=INFO" \
  --quiet

URL=$(gcloud run services describe "$SERVICE" \
  --region="$REGION" \
  --project="$PROJECT_ID" \
  --format='value(status.url)')
echo "Service URL: $URL"
