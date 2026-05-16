#!/bin/sh
set -e

configure_timezone() {
    if [ -n "$TZ" ] && [ -f "/usr/share/zoneinfo/$TZ" ]; then
        echo "[$(date)] Configuring timezone: $TZ"
        ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime
        echo "$TZ" > /etc/timezone
    elif [ -n "$TZ" ]; then
        echo "Warning: Timezone '$TZ' not found, keeping UTC"
    fi
}

configure_timezone

exec /app/fail2ban-ui "$@"