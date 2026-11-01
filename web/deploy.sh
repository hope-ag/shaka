#!/usr/bin/env bash
# Build and deploy the web UI to Cloud Run, creating what it needs on the first run.
# Usage: CA_KEY=path/to/user_ca ./deploy.sh ca.example.com
# CA_KEY is only read on the first run, to store the key in Secret Manager.
# REGION must be one that supports domain mappings (see README); SERVICE and BUCKET can be overridden.
set -euo pipefail
DOMAIN=${1:?usage: CA_KEY=path/to/user_ca deploy.sh DOMAIN}
PROJECT=$(gcloud config get-value project 2>/dev/null)
REGION=${REGION:-europe-west1}
SERVICE=${SERVICE:-ssh-ca}
BUCKET=${BUCKET:-$PROJECT-ssh-ca}
SA=ssh-ca-run@$PROJECT.iam.gserviceaccount.com
cd "$(dirname "$0")"

go test ./...

gcloud services enable run.googleapis.com secretmanager.googleapis.com \
  artifactregistry.googleapis.com cloudbuild.googleapis.com

# A dedicated identity, so the service can read its two secrets and its bucket and nothing else.
gcloud iam service-accounts describe "$SA" >/dev/null 2>&1 ||
  gcloud iam service-accounts create ssh-ca-run --display-name "ssh-ca Cloud Run"

if ! gcloud storage buckets describe "gs://$BUCKET" >/dev/null 2>&1; then
  gcloud storage buckets create "gs://$BUCKET" --location="$REGION" \
    --uniform-bucket-level-access --public-access-prevention
  gcloud storage buckets update "gs://$BUCKET" --versioning
fi
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member="serviceAccount:$SA" --role=roles/storage.objectUser >/dev/null

if ! gcloud secrets describe ssh-ca-key >/dev/null 2>&1; then
  : "${CA_KEY:?first run: set CA_KEY to the CA private key file (user_ca)}"
  gcloud secrets create ssh-ca-key --data-file="$CA_KEY" --replication-policy=automatic
  # The service has no terminal to prompt on, so an encrypted key needs its passphrase stored too.
  if ! ssh-keygen -y -P "" -f "$CA_KEY" >/dev/null 2>&1; then
    printf 'CA key passphrase: ' >&2
    read -rs CA_PASS
    printf '\n' >&2
    printf %s "$CA_PASS" | gcloud secrets create ssh-ca-pass --data-file=- --replication-policy=automatic
  fi
fi
grant() {
  gcloud secrets add-iam-policy-binding "$1" \
    --member="serviceAccount:$SA" --role=roles/secretmanager.secretAccessor >/dev/null
}
grant ssh-ca-key
SECRETS=/secrets/key/user_ca=ssh-ca-key:latest
ENV=LITESTREAM_BUCKET=$BUCKET
if gcloud secrets describe ssh-ca-pass >/dev/null 2>&1; then
  grant ssh-ca-pass
  SECRETS+=,/secrets/pass/passphrase=ssh-ca-pass:latest
  ENV+=,CA_PASSPHRASE_FILE=/secrets/pass/passphrase
fi

# One instance at most: SQLite has a single writer, and the login throttle lives in memory.
gcloud run deploy "$SERVICE" --source . --region "$REGION" \
  --service-account "$SA" --allow-unauthenticated \
  --min-instances 0 --max-instances 1 --memory 256Mi --cpu 1 \
  --execution-environment gen2 \
  --set-secrets "$SECRETS" --set-env-vars "$ENV"

if ! gcloud beta run domain-mappings describe --domain "$DOMAIN" --region "$REGION" >/dev/null 2>&1; then
  gcloud beta run domain-mappings create --service "$SERVICE" --domain "$DOMAIN" --region "$REGION"
fi
echo "Add these DNS records for $DOMAIN (DNS only, not proxied, if it is on Cloudflare):"
gcloud beta run domain-mappings describe --domain "$DOMAIN" --region "$REGION" \
  --format='yaml(status.resourceRecords)'
echo "First deploy? Create your login: ./admin.sh NAME root,NAME"
