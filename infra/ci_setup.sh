#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-wide-factor-387115}"
BUILDER_SA_NAME="${BUILDER_SA_NAME:-soc-triage-builder}"
BUILDER_SA="${BUILDER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
RUNTIME_SA="${RUNTIME_SA:-soc-triage-runtime@${PROJECT_ID}.iam.gserviceaccount.com}"

gcloud config set project "$PROJECT_ID" >/dev/null

gcloud services enable cloudbuild.googleapis.com --project "$PROJECT_ID"

if ! gcloud iam service-accounts describe "$BUILDER_SA" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$BUILDER_SA_NAME" \
    --display-name="SOC triage Cloud Build builder" \
    --project "$PROJECT_ID"
fi

# Build execution: logging, workspace storage, Artifact Registry upload.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${BUILDER_SA}" \
  --role="roles/cloudbuild.builds.builder" \
  --condition=None \
  --quiet >/dev/null

# Deploy the Cloud Run service.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${BUILDER_SA}" \
  --role="roles/run.admin" \
  --condition=None \
  --quiet >/dev/null

# Act as the runtime service account only; no project-wide actAs.
gcloud iam service-accounts add-iam-policy-binding "$RUNTIME_SA" \
  --member="serviceAccount:${BUILDER_SA}" \
  --role="roles/iam.serviceAccountUser" \
  --project "$PROJECT_ID" \
  --quiet >/dev/null

echo "Builder service account: $BUILDER_SA"
echo "Runtime service account:  $RUNTIME_SA"
