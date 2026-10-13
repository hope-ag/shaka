#!/usr/bin/env bash
# Build locally, install binary + systemd unit on the CA box, (re)start it.
# Usage: ./deploy.sh user@ca-box        (GOARCH=arm64 ./deploy.sh ... for ARM VMs)
set -euo pipefail
TARGET=${1:?usage: deploy.sh user@host}
cd "$(dirname "$0")"

go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=${GOARCH:-amd64} go build -trimpath -ldflags="-s -w" -o ssh-ca-web .
scp -q ssh-ca-web "$TARGET":/tmp/ssh-ca-web
rm ssh-ca-web

ssh -t "$TARGET" 'sudo bash -s' <<'EOF'
set -euo pipefail
install -m 755 /tmp/ssh-ca-web /usr/local/bin/ssh-ca-web && rm /tmp/ssh-ca-web
install -d -m 700 /var/lib/ssh-ca-web

# Passphrase-protected CA key: put the passphrase in /etc/ssh-ca/passphrase (chmod 600).
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
