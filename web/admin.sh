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
# v0.5.17 loses its Google login during `replicate` when it runs on your own gcloud credentials
# (the service is unaffected), so upload with the commit that fixes it (litestream PR #1602).
# ponytail: switch back to a release tag once one ships with that fix.
LITESTREAM_UPLOAD="go run github.com/benbjohnson/litestream/cmd/litestream@bc91f744a4f5271381a8d53c102121a4232845e5"
cd "$(dirname "$0")"

# Litestream reads the same Application Default Credentials the Google libraries use.
gcloud auth application-default print-access-token >/dev/null 2>&1 ||
  { echo "Run 'gcloud auth application-default login' first." >&2; exit 1; }

# The temporary copy holds password hashes and authenticator secrets, and a paused service
# is an outage, so clean up and resume however the script ends, Ctrl-C included.
WORK=$(mktemp -d)
resume() {
  rm -rf "$WORK"
  gcloud run services update "$SERVICE" --region "$REGION" --scaling=auto --max-instances 1 ||
    echo "Resume failed. Run: gcloud run services update $SERVICE --region $REGION --scaling=auto --max-instances 1" >&2
}
cat > "$WORK/litestream.yml" <<EOF
dbs:
  - path: $WORK/ca.db
    replica:
      url: gs://$BUCKET/ca.db
EOF

trap resume EXIT
gcloud run services update "$SERVICE" --region "$REGION" --scaling=0
sleep 15 # give the last instance time to upload its final writes

$LITESTREAM restore -config "$WORK/litestream.yml" -if-replica-exists "$WORK/ca.db"
go run . -db "$WORK/ca.db" adduser "$NAME" "$PRINCIPALS"
$LITESTREAM_UPLOAD replicate -config "$WORK/litestream.yml" -once

# Read the account back from the bucket with the release the service runs, rather than
# trusting the upload. (adduser has already checked NAME is plain letters and digits.)
$LITESTREAM restore -o "$WORK/check.db" "gs://$BUCKET/ca.db"
if [ "$(sqlite3 "$WORK/check.db" "SELECT count(*) FROM users WHERE name='$NAME'")" != 1 ]; then
  echo "The bucket still has no account named $NAME, so the upload did not land. Nothing was changed." >&2
  exit 1
fi
echo "Checked: gs://$BUCKET/ca.db has the account $NAME."

