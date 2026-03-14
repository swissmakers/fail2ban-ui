# Reverse Proxy Deployment Guide

This guide provides production-redy guidance for running Fail2Ban UI behind a reverse proxy.

## Why this matters

Fail2Ban UI includes administrative capabilities and callback endpoints. A reverse proxy lets you apply TLS, access controls, and standardized HTTP security policies before traffic reaches the UI.

## Basic architecture

```text
Browser / Fail2Ban hosts
          |
      HTTPS (443)
          |
 Reverse Proxy (TLS termination)
          |
HTTP (127.0.0.1:8080)
          |
      Fail2Ban UI
```

Recommended runtime settings for the above example:

- `BIND_ADDRESS=127.0.0.1` (when proxy and UI run on the same host)
- `PORT=8080` (or another local port)
- `OIDC_ENABLED=true` for user authentication (optional but recommended)

## Reverse proxy requirements

For correct UI behavior (including WebSocket live updates), the proxy must:

1. Preserve `Host` and `Origin` consistency.
2. Allow WebSocket upgrades on `GET /api/ws`.
3. Forward client IP context (`X-Forwarded-For`, `X-Forwarded-Proto`).

## Nginx reference configuration

Use this as a baseline and adapt to your hostnames and certificates.

```nginx
server {
    listen 80;
    server_name fail2ban.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name fail2ban.example.com;

    ssl_certificate     /etc/letsencrypt/live/fail2ban.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/fail2ban.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache   shared:SSL:10m;

    # Optional strict transport security (don't forget to preload via -> https://hstspreload.org/)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;

    # Optional source allowlist
    # allow 10.0.0.0/8;
    # allow 192.168.0.0/16;
    # deny all;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }

    # Proxy WebSocket endpoint
    location /api/ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

## Caddy reference configuration

```caddy
fail2ban.example.com {
    encode zstd gzip

    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "no-referrer"
    }

    reverse_proxy 127.0.0.1:8080
}
```

Caddy automatically handles TLS and WebSocket upgrades for this basic setup.

## Validation checklist / some tests

1. Validate UI: `curl -Ik https://fail2ban.example.com/`
2. Validate API reachability: `curl -s https://fail2ban.example.com/api/version`
3. Validate WebSocket in browser dev tools:
   - status `101 Switching Protocols` for `/api/ws`
   - live ban/unban events update without refresh
4. Validate callback path from managed Fail2Ban hosts to configured `CALLBACK_URL`