# Reverse Proxy Deployment Guide

This guide provides some guidance for running Fail2Ban UI behind a reverse proxy.

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
2. Allow WebSocket upgrades on the real-time endpoint (`GET /api/ws` at site root, or `GET {BASE_PATH}/api/ws` when using a subpath).
3. Forward client IP context (`X-Forwarded-For`, `X-Forwarded-Proto`).

If the proxy **strips** a path prefix before forwarding (e.g. external `/myf2b/` -> upstream `/`), leave `BASE_PATH` unset on Fail2Ban UI and configure the app as if it lived at root; only the public URLs change. If the app receives the **full** path including `/myf2b`, set `BASE_PATH=/myf2b` on Fail2Ban UI and forward that prefix unchanged.

## Subpath (`BASE_PATH`)

When Fail2Ban UI runs with `BASE_PATH=/myf2b` (see [`docs/configuration.md`](https://github.com/swissmakers/fail2ban-ui/blob/main/docs/configuration.md)):

- Proxy `location` should match the prefix and pass the **same** path to the backend (no strip), e.g. `https://host/myf2b/api/version` -> upstream `http://127.0.0.1:8080/myf2b/api/version`.
- WebSocket URL in the browser becomes `wss://host/myf2b/api/ws`.
- Set `CALLBACK_URL` and `OIDC_REDIRECT_URL` to include `/myf2b` as in the configuration reference.

Nginx example (HTTPS server; adjust TLS paths):

```nginx
location /myf2b/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 60s;
    proxy_send_timeout 60s;
}

location /myf2b/api/ws {
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
```

Use `proxy_pass http://127.0.0.1:8080;` (no URI suffix) so the request URI `/myf2b/...` is forwarded as-is. If you use a **trailing** URI on `proxy_pass`, Nginx rewrites the path and you must match that behavior to `BASE_PATH` (usually avoid stripping unless `BASE_PATH` is unset on the app).

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

1. Validate UI: `curl -Ik https://fail2ban.example.com/` (or `https://fail2ban.example.com/myf2b/` with `BASE_PATH`)
2. Validate API reachability: `curl -s https://fail2ban.example.com/api/version` (or `.../myf2b/api/version`)
3. Validate WebSocket in browser dev tools:
   - status `101 Switching Protocols` for `/api/ws` or `/myf2b/api/ws`
   - live ban/unban events update without refresh
4. Validate callback path from managed Fail2Ban hosts to configured `CALLBACK_URL`