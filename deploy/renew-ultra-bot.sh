#!/bin/sh
# Install into /etc/letsencrypt/renewal-hooks/deploy/ with mode 0755.
# File-based TLS loads the renewed certificate when the bot restarts.
set -eu
systemctl try-restart ultra-bot.service
