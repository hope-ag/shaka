#!/usr/bin/env bash
# Puts Cloudflare Access in front of the web UI, leaving /revoked_keys public for servers.
# Needs: CF_API_TOKEN (Account > Access: Apps and Policies > Edit), CF_ACCOUNT_ID.
# Usage: ./access.sh ca.my_site.dev you@example.com
set -euo pipefail
HOST=${1:?usage: access.sh HOSTNAME EMAIL}
EMAIL=${2:?usage: access.sh HOSTNAME EMAIL}
: "${CF_API_TOKEN:?}" "${CF_ACCOUNT_ID:?}"
API=https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/access/apps

app() { # name domain decision include-json
  curl -fsS -X POST "$API" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{
    \"name\": \"$1\", \"domain\": \"$2\", \"type\": \"self_hosted\", \"session_duration\": \"12h\",
    \"app_launcher_visible\": false,
    \"policies\": [{\"name\": \"$1\", \"decision\": \"$3\", \"include\": [$4]}]
  }" | python3 -c "import json,sys;r=json.load(sys.stdin);print('$1:', 'ok' if r['success'] else r['errors'])"
}

# More specific path wins, so servers can still fetch the ban list.
app "ssh-ca revoked_keys" "$HOST/revoked_keys" bypass '{"everyone":{}}'
app "ssh-ca" "$HOST" allow "{\"email\":{\"email\":\"$EMAIL\"}}"

echo "Check: curl -sI https://$HOST/ should 302 to cloudflareaccess.com; curl -s https://$HOST/revoked_keys should 200."
