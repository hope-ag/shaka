#!/usr/bin/env bash
# Build locally, install binary + systemd unit on the CA box, (re)start it.
# Usage: ./deploy.sh INSTANCE [extra gcloud flags, e.g. --zone=europe-west1-b --tunnel-through-iap]
# Uses gcloud compute ssh/scp, so OS Login / IAM access applies. GOARCH=arm64 for ARM VMs.
# Asks once for the CA key passphrase if the key is encrypted and the box has none stored.
set -euo pipefail
INSTANCE=${1:?usage: deploy.sh INSTANCE [gcloud flags]}
shift
cd "$(dirname "$0")"

go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=${GOARCH:-amd64} go build -trimpath -ldflags="-s -w" -o ssh-ca-web .
gcloud compute scp "$@" ssh-ca-web "$INSTANCE":/tmp/ssh-ca-web
rm ssh-ca-web

# The service has no terminal to prompt on, so an encrypted CA key needs its passphrase
# in a root-only file. Skip the prompt when the key has no passphrase or the file exists.
PASS_B64=""
if ! gcloud compute ssh "$INSTANCE" "$@" --command \
  'sudo test -f /etc/ssh-ca/passphrase || sudo ssh-keygen -y -P "" -f /etc/ssh-ca/user_ca >/dev/null 2>&1' >/dev/null 2>&1; then
  [ -t 0 ] || { echo "The CA key is encrypted, so the script needs a terminal to ask for its passphrase. Run it yourself." >&2; exit 1; }
  printf 'CA key passphrase: ' >&2
  read -rs CA_PASS
  printf '\n' >&2
  PASS_B64=$(printf %s "$CA_PASS" | base64 | tr -d '\n')
fi

{ printf 'PASS_B64=%s\n' "$PASS_B64"; cat <<'EOF'
set -euo pipefail
install -m 755 /tmp/ssh-ca-web /usr/local/bin/ssh-ca-web && rm /tmp/ssh-ca-web
install -d -m 700 /var/lib/ssh-ca-web

if [ -n "$PASS_B64" ]; then
  install -d -m 700 /etc/ssh-ca
  (umask 077; printf %s "$PASS_B64" | base64 -d > /etc/ssh-ca/passphrase)
fi
CRED=""
[ -f /etc/ssh-ca/passphrase ] && CRED=$'LoadCredential=ca_pass:/etc/ssh-ca/passphrase\nEnvironment=CA_PASSPHRASE_FILE=%d/ca_pass'

cat > /etc/systemd/system/ssh-ca-web.service <<UNIT
[Unit]
Description=SSH CA web UI
After=network.target

[Service]
ExecStart=/usr/local/bin/ssh-ca-web
$CRED
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
ReadWritePaths=/var/lib/ssh-ca-web
ReadOnlyPaths=/etc/ssh-ca
MemoryMax=128M
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable ssh-ca-web >/dev/null
systemctl restart ssh-ca-web
sleep 1
systemctl is-active ssh-ca-web && curl -fsS -o /dev/null -w "local check: %{http_code}\n" http://127.0.0.1:8080/ \
  || { journalctl -u ssh-ca-web -n 20 --no-pager; exit 1; }
echo "First deploy? Create a user: sudo ssh-ca-web adduser NAME root,NAME"
EOF
} | gcloud compute ssh "$INSTANCE" "$@" --command 'sudo bash -s'
