#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-wide-factor-387115}"
REGION="${REGION:-us-central1}"
DATASET="${BQ_DATASET:-triage}"
AR_REPO="${AR_REPO:-soc-triage}"
RUNTIME_SA_NAME="${RUNTIME_SA_NAME:-soc-triage-runtime}"
RUNTIME_SA="${RUNTIME_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud config set project "$PROJECT_ID" >/dev/null

gcloud services enable \
  aiplatform.googleapis.com \
  bigquery.googleapis.com \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  iam.googleapis.com \
  --project "$PROJECT_ID"

if ! gcloud iam service-accounts describe "$RUNTIME_SA" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$RUNTIME_SA_NAME" \
    --display-name="SOC triage runtime" \
    --project "$PROJECT_ID"
fi

# Dataset-scoped read access. Dataset IAM via bq add-iam-policy-binding is
# allowlisted in this project, so use the equivalent dataset ACL (READER) and
# avoid a project-wide BigQuery data role.
PROJECT_ID="$PROJECT_ID" BQ_DATASET="$DATASET" RUNTIME_SA="$RUNTIME_SA" \
  uv run python infra/grant_dataset_read.py

# Query execution requires jobs.create, which dataset viewer does not include.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role="roles/bigquery.jobUser" \
  --condition=None \
  --quiet >/dev/null

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role="roles/aiplatform.user" \
  --condition=None \
  --quiet >/dev/null

if ! gcloud artifacts repositories describe "$AR_REPO" \
  --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud artifacts repositories create "$AR_REPO" \
    --repository-format=docker \
    --location="$REGION" \
    --description="SOC triage agent images" \
    --project="$PROJECT_ID"
fi

# The dataset was created under the BigQuery sandbox, which set a 60-day
# expiration. Billing is enabled now, so remove retention surprises.
bq update --expiration 0 "${PROJECT_ID}:${DATASET}.indicators"
bq update --default_table_expiration 0 --default_partition_expiration 0 \
  "${PROJECT_ID}:${DATASET}"

echo "Runtime service account: $RUNTIME_SA"
echo "Dataset: ${PROJECT_ID}:${DATASET}"
echo "Artifact Registry: ${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
