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

**Path-prefix handling:** To serve the UI under a subpath such as `/myf2b/`, set `BASE_PATH=/myf2b` and forward the request path to the application *unchanged*. Do not strip the prefix in the proxy. The application builds every link, static asset, API, WebSocket, and OIDC URL from `BASE_PATH`. If the proxy strips the prefix and `BASE_PATH` is unset, the page loads without styles because the browser requests `/static/...` at the site root, which the proxy does not route to the application. If the proxy strips the prefix and `BASE_PATH` is set, `/` redirects to `/myf2b/`, the proxy strips it again, and the browser ends in a redirect loop.

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

**Important:** Use `proxy_pass http://127.0.0.1:8080;` without a URI suffix so the request URI `/myf2b/...` is forwarded as-is. A URI suffix such as `proxy_pass http://127.0.0.1:8080/;` makes Nginx strip the prefix, and the UI then breaks as described under "Path-prefix handling".

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

## Caddy subpath configuration

Use this when Fail2Ban UI shares a hostname with other content and lives under a subpath. Run the application with `BASE_PATH=/myf2b` and use `handle`, which keeps the request path. Do not use `handle_path` or `uri strip_prefix`, because both remove the prefix before the request reaches the application.

```caddy
example.com {
    encode zstd gzip

    # Fail2Ban UI under /myf2b (BASE_PATH=/myf2b on the application)
    @f2b path /myf2b /myf2b/*
    handle @f2b {
        header {
            X-Content-Type-Options "nosniff"
            X-Frame-Options "DENY"
            Referrer-Policy "no-referrer"
        }
        reverse_proxy 127.0.0.1:8080
    }

    # Everything else on this hostname
    handle {
        root * /var/www/html
        file_server
    }
}
```

The matcher lists `/myf2b` and `/myf2b/*` so that both `https://example.com/myf2b` and `https://example.com/myf2b/` reach the UI. Requests to `https://example.com/` and other paths never touch the application, so `/static`, `/api`, and `/auth` stay free for the other site. Set `CALLBACK_URL=https://example.com/myf2b` and, with OIDC, `OIDC_REDIRECT_URL=https://example.com/myf2b/auth/callback`.

## Verification

1. UI reachable: `curl -Ik https://fail2ban.example.com/` (or `https://fail2ban.example.com/myf2b/` with `BASE_PATH`).
2. API reachable: `curl -s https://fail2ban.example.com/api/version` (or `.../myf2b/api/version`).
3. WebSocket working, in the browser developer tools:
   * `101 Switching Protocols` for `/api/ws` or `/myf2b/api/ws`
   * Live ban/unban events appear without a page refresh
4. Callback path reachable from every managed Fail2Ban host to the configured `CALLBACK_URL`.

## Subpath problems

* **Page loads without styles, and the browser shows 404 for `/static/...` or `/locales/...` at the site root.** The proxy strips the prefix and `BASE_PATH` is unset. Set `BASE_PATH` and forward the prefix unchanged.
* **Redirect loop between `/` and `/myf2b/`.** `BASE_PATH` is set but the proxy strips the prefix. Remove the strip (`handle_path`, `uri strip_prefix`, or a `proxy_pass` URI suffix).
* **404 for `https://host/myf2b/`.** `BASE_PATH` on the application does not match the public prefix, for example `BASE_PATH=/f2b` with a `/myf2b/` location. The application serves only the configured prefix and returns 404 for every other path.
