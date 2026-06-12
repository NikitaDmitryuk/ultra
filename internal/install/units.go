package install

const RelaySystemdUnit = `[Unit]
Description=ultra two-tier edge relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ultra-relay
Group=ultra-relay
EnvironmentFile=-/etc/ultra-relay/environment
StateDirectory=ultra-relay
ExecStart=/usr/local/bin/ultra-relay -spec /etc/ultra-relay/spec.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

const BotSystemdUnit = `[Unit]
Description=Ultra Relay Telegram Bot
Documentation=https://github.com/NikitaDmitryuk/ultra
After=network-online.target ultra-relay.service
Wants=network-online.target
Requires=ultra-relay.service

[Service]
Type=simple
WorkingDirectory=/etc/ultra-relay

EnvironmentFile=/etc/ultra-relay/environment
EnvironmentFile=/etc/ultra-relay/bot.env

ExecStart=/usr/local/bin/ultra-bot \
    -spec /etc/ultra-relay/spec.json \
    -admin-api-url http://127.0.0.1:8443 \
    -domain ${ULTRA_BOT_DOMAIN} \
    -port ${ULTRA_BOT_PORT} \
    -cert-file /etc/letsencrypt/live/${ULTRA_BOT_DOMAIN}/fullchain.pem \
    -key-file /etc/letsencrypt/live/${ULTRA_BOT_DOMAIN}/privkey.pem \
    -data-dir /var/lib/ultra-bot \
    -log-level ${ULTRA_RELAY_LOG_LEVEL}
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ultra-bot

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/ultra-bot /etc/ultra-relay
ReadOnlyPaths=/etc/letsencrypt

[Install]
WantedBy=multi-user.target
`
