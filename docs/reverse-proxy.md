# Reverse proxy guide

This guide describes how to run Fail2Ban UI behind a reverse proxy.

## Why this matters

Fail2Ban UI exposes administrative capabilities and callback endpoints. A reverse proxy lets you apply TLS, access controls, and standardized HTTP security policies before traffic reaches the application.

## Basic architecture

```text
Browser / Fail2Ban hosts
          |
      HTTPS (443)
          |
 Reverse proxy (TLS termination)
          |
HTTP (127.0.0.1:8080)
          |
      Fail2Ban UI
```

Recommended runtime settings for this layout:

* `BIND_ADDRESS=127.0.0.1` when proxy and UI run on the same host
* `PORT=8080` or another local port
* `OIDC_ENABLED=true` for user authentication (optional but recommended)

## Proxy requirements

For correct behavior, including WebSocket live updates, the proxy must:

1. Preserve `Host` and `Origin` consistency. The WebSocket endpoint rejects connections where the two do not match.
2. Allow WebSocket upgrades on the real-time endpoint: `GET /api/ws` at the site root, or `GET {BASE_PATH}/api/ws` when using a subpath.
3. Forward client IP context: `X-Forwarded-For` and `X-Forwarded-Proto`.

**Path-prefix handling:** If the proxy *strips* a path prefix before forwarding (external `/myf2b/` -> upstream `/`), leave `BASE_PATH` unset and configure the application as if it lived at the root; only the public URLs change. If the application receives the *full* path including `/myf2b`, set `BASE_PATH=/myf2b` and forward the prefix unchanged.

## Subpath deployment (`BASE_PATH`)

When Fail2Ban UI runs with `BASE_PATH=/myf2b` (see [configuration.md](configuration.md)):

* The proxy `location` must match the prefix and pass the *same* path to the backend, with no strip: `https://host/myf2b/api/version` -> upstream `http://127.0.0.1:8080/myf2b/api/version`.
* The WebSocket URL in the browser becomes `wss://host/myf2b/api/ws`.
* `CALLBACK_URL` and `OIDC_REDIRECT_URL` must include `/myf2b`, as described in the configuration reference.

Nginx example (inside an HTTPS server block; adjust TLS paths):

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

**Important:** Use `proxy_pass http://127.0.0.1:8080;` without a URI suffix so the request URI `/myf2b/...` is forwarded as-is. If you append a URI to `proxy_pass`, Nginx rewrites the path, and that rewrite must match the application's `BASE_PATH`. In practice, avoid stripping unless `BASE_PATH` is unset on the application.

## Nginx reference configuration

Use this as a baseline and adapt the hostnames and certificates.

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

    # Optional strict transport security (register at https://hstspreload.org/ before preloading)
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

    # WebSocket endpoint
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

Caddy handles TLS and WebSocket upgrades automatically for this basic setup.

## Verification

1. UI reachable: `curl -Ik https://fail2ban.example.com/` (or `https://fail2ban.example.com/myf2b/` with `BASE_PATH`).
2. API reachable: `curl -s https://fail2ban.example.com/api/version` (or `.../myf2b/api/version`).
3. WebSocket working, in the browser developer tools:
   * `101 Switching Protocols` for `/api/ws` or `/myf2b/api/ws`
   * Live ban/unban events appear without a page refresh
4. Callback path reachable from every managed Fail2Ban host to the configured `CALLBACK_URL`.
