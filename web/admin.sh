#!/usr/bin/env bash
# Create or reset an admin, which replaces running `ssh-ca-web adduser` on a box.
# Usage: ./admin.sh NAME root,NAME   (same REGION/SERVICE/BUCKET overrides as deploy.sh)
# Pauses the service so nothing else writes, restores the database from the bucket into a
# temporary folder here, runs adduser on it, uploads the change and turns the service back on.
set -euo pipefail
NAME=${1:?usage: admin.sh NAME PRINCIPALS}
PRINCIPALS=${2:?usage: admin.sh NAME PRINCIPALS}
PROJECT=$(gcloud config get-value project 2>/dev/null)
REGION=${REGION:-europe-west1}
SERVICE=${SERVICE:-ssh-ca}
BUCKET=${BUCKET:-$PROJECT-ssh-ca}
LITESTREAM="go run github.com/benbjohnson/litestream/cmd/litestream@v0.5.17"
cd "$(dirname "$0")"

# Litestream reads the same Application Default Credentials the Google libraries use.
gcloud auth application-default print-access-token >/dev/null 2>&1 ||
  { echo "Run 'gcloud auth application-default login' first." >&2; exit 1; }

WORK=$(mktemp -d)
cat > "$WORK/litestream.yml" <<EOF
dbs:
  - path: $WORK/ca.db
    replica:
      url: gs://$BUCKET/ca.db
EOF

gcloud run services update "$SERVICE" --region "$REGION" --scaling=0
trap 'echo "The service is still paused. Resume it with: gcloud run services update $SERVICE --region $REGION --scaling=auto --max-instances 1" >&2' ERR
sleep 15 # give the last instance time to upload its final writes

$LITESTREAM restore -config "$WORK/litestream.yml" -if-replica-exists "$WORK/ca.db"
go run . -db "$WORK/ca.db" adduser "$NAME" "$PRINCIPALS"
$LITESTREAM replicate -config "$WORK/litestream.yml" -once

gcloud run services update "$SERVICE" --region "$REGION" --scaling=auto --max-instances 1
rm -rf "$WORK"
