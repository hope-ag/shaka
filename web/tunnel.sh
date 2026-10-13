#!/usr/bin/env bash
# Run on the CA box: sudo ./tunnel.sh ca.example.com
# Exposes 127.0.0.1:8080 via a Cloudflare Tunnel. No inbound ports needed.
set -euo pipefail
HOST=${1:?usage: tunnel.sh HOSTNAME}
NAME=ssh-ca

if ! command -v cloudflared >/dev/null; then
  mkdir -p --mode=0755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
    > /etc/apt/sources.list.d/cloudflared.list
  apt-get update && apt-get install -y cloudflared
fi

# Opens a URL: visit it, pick the zone for $HOST.
[ -f ~/.cloudflared/cert.pem ] || cloudflared tunnel login

cloudflared tunnel info "$NAME" >/dev/null 2>&1 || cloudflared tunnel create "$NAME"
ID=$(cloudflared tunnel list -o json | python3 -c "import json,sys;print(next(t['id'] for t in json.load(sys.stdin) if t['name']=='$NAME'))")

mkdir -p /etc/cloudflared
cp ~/.cloudflared/"$ID".json /etc/cloudflared/
chmod 600 /etc/cloudflared/"$ID".json
cat > /etc/cloudflared/config.yml <<EOF
tunnel: $ID
credentials-file: /etc/cloudflared/$ID.json
ingress:
  - hostname: $HOST
    service: http://127.0.0.1:8080
  - service: http_status:404
EOF

cloudflared tunnel route dns "$NAME" "$HOST" || echo "DNS record exists? Delete any old A/CNAME for $HOST and rerun."
cloudflared service install 2>/dev/null || systemctl restart cloudflared
systemctl enable --now cloudflared
sleep 3
curl -fsS -o /dev/null -w "https://$HOST -> %{http_code}\n" "https://$HOST/" || echo "Not up yet; check: journalctl -u cloudflared"
