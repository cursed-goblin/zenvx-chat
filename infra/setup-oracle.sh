#!/usr/bin/env bash
# ZenvX relay + TURN bootstrap for a fresh Oracle Cloud Always Free instance
# (Ubuntu 22.04/24.04, ARM Ampere A1). Idempotent — safe to re-run.
#
#   sudo bash infra/setup-oracle.sh chat.example.org you@example.org
#
# Total recurring cost: 0. Always Free covers 4 ARM vCPU / 24 GB RAM /
# 10 TB egress per month; this workload uses well under 1% of that.

set -euo pipefail

DOMAIN="${1:?usage: setup-oracle.sh <domain> <email>}"
EMAIL="${2:?usage: setup-oracle.sh <domain> <email>}"
TURN_SECRET="$(openssl rand -hex 32)"
DATA_DIR=/var/lib/zenvx

echo "==> Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nodejs npm coturn nginx certbot python3-certbot-nginx ufw jq

echo "==> Creating service user and data dir"
id -u zenvx &>/dev/null || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin zenvx
mkdir -p "$DATA_DIR/queue"
chown -R zenvx:zenvx "$DATA_DIR"

echo "==> Installing relay to /opt/zenvx"
mkdir -p /opt/zenvx
cp -r server tools client package.json /opt/zenvx/ 2>/dev/null || true
chown -R zenvx:zenvx /opt/zenvx

# The directory and root public key must be copied in by the operator.
if [ ! -f "$DATA_DIR/members.json" ]; then
  echo "    NOTE: copy your signed directory/members.json to $DATA_DIR/members.json"
  cp directory/members.json "$DATA_DIR/members.json" 2>/dev/null || true
  chown zenvx:zenvx "$DATA_DIR/members.json" 2>/dev/null || true
fi

echo "==> Configuring coturn"
cat >/etc/turnserver.conf <<EOF
# Managed by setup-oracle.sh
listening-port=3478
tls-listening-port=5349
fingerprint
lt-cred-mech
use-auth-secret
static-auth-secret=${TURN_SECRET}
realm=${DOMAIN}
server-name=${DOMAIN}
total-quota=200
bps-capacity=0
stale-nonce=600
no-multicast-peers
no-cli
# Never let TURN be abused as an open proxy into private networks.
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
cert=/etc/letsencrypt/live/${DOMAIN}/fullchain.pem
pkey=/etc/letsencrypt/live/${DOMAIN}/privkey.pem
EOF
sed -i 's/^#TURNSERVER_ENABLED/TURNSERVER_ENABLED/' /etc/default/coturn 2>/dev/null || true
echo 'TURNSERVER_ENABLED=1' >/etc/default/coturn

echo "==> Installing systemd unit"
cat >/etc/systemd/system/zenvx-relay.service <<EOF
[Unit]
Description=ZenvX Chat relay (signalling + store-and-forward)
After=network.target

[Service]
Type=simple
User=zenvx
WorkingDirectory=/opt/zenvx
Environment=PORT=8080
Environment=ZENVX_DATA=${DATA_DIR}
Environment=ZENVX_DIRECTORY=${DATA_DIR}/members.json
ExecStart=/usr/bin/node /opt/zenvx/server/relay.mjs
Restart=always
RestartSec=3
# Hardening: the relay handles untrusted input from the public internet.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF

echo "==> Configuring nginx reverse proxy (WebSocket-aware)"
cat >/etc/nginx/sites-available/zenvx <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF
ln -sf /etc/nginx/sites-available/zenvx /etc/nginx/sites-enabled/zenvx
rm -f /etc/nginx/sites-enabled/default
nginx -t

echo "==> Firewall"
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3478/tcp
ufw allow 3478/udp
ufw allow 5349/tcp
ufw allow 5349/udp
ufw allow 49152:65535/udp   # TURN relay range
ufw --force enable

# Oracle images ship with a REJECT-all iptables chain that survives ufw.
iptables -I INPUT -p tcp --dport 80 -j ACCEPT || true
iptables -I INPUT -p tcp --dport 443 -j ACCEPT || true
iptables -I INPUT -p udp --dport 3478 -j ACCEPT || true
netfilter-persistent save 2>/dev/null || true

echo "==> TLS certificate"
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect || \
  echo "    certbot failed — check that ${DOMAIN} resolves to this box, then re-run"

systemctl daemon-reload
systemctl enable --now coturn zenvx-relay nginx
systemctl restart coturn zenvx-relay nginx

cat <<EOF

=============================================================
 ZenvX relay is up.

  Relay URL   : https://${DOMAIN}
  Health      : curl https://${DOMAIN}/health
  TURN secret : ${TURN_SECRET}

 Put this in directory/members.json under "ice" so clients can
 traverse NAT, then re-sign the directory:

   { "urls": "turn:${DOMAIN}:3478?transport=udp",
     "username": "<unix-ts>:zenvx",
     "credential": "<base64 hmac-sha1 of username with the TURN secret>" }

 Save the TURN secret now — it is not stored anywhere else.
=============================================================
EOF
