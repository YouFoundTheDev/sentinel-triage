#!/usr/bin/env bash
set -euo pipefail

# Requires an existing Cloud Build GitHub connection/repository resource.
# Create the connection first in the Cloud Build console:
#   Repositories -> Connect repository -> GitHub (Cloud Build GitHub App)
# Then set GITHUB_OWNER, GITHUB_REPO, and CONNECTION below.

: "${GITHUB_OWNER:?set GITHUB_OWNER to the GitHub owner/org}"
: "${GITHUB_REPO:?set GITHUB_REPO to the GitHub repository name}"
: "${CONNECTION:?set CONNECTION to the Cloud Build GitHub connection name}"

PROJECT_ID="${PROJECT_ID:-wide-factor-387115}"
REGION="${REGION:-us-central1}"
BUILDER_SA="${BUILDER_SA:-soc-triage-builder@${PROJECT_ID}.iam.gserviceaccount.com}"
SERVICE="${SERVICE:-soc-triage-agent}"
TRIGGER="${TRIGGER:-soc-triage-main}"

gcloud builds triggers create github \
  --name="$TRIGGER" \
  --description="Build, test, and deploy SOC triage on pushes to main" \
  --repository="projects/${PROJECT_ID}/locations/${REGION}/connections/${CONNECTION}/repositories/${GITHUB_REPO}" \
  --branch-pattern='^main$' \
  --build-config=cloudbuild.yaml \
  --service-account="projects/${PROJECT_ID}/serviceAccounts/${BUILDER_SA}" \
  --region="$REGION" \
  --project="$PROJECT_ID"

echo "Trigger created: $TRIGGER"
