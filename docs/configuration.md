# Configuration reference

This document describes common runtime settings and related operational behavior. Most runtime options are configured in the UI and stored in the database. Environment variables override behavior where applicable.

## Network and listener settings

- `PORT`  
  HTTP listen port. Default: `8080`.
- `BIND_ADDRESS`  
  Listen address. Default: `0.0.0.0`.  
  Recommended with local reverse proxy: `127.0.0.1`.

Example:

```bash
-e PORT=3080 -e BIND_ADDRESS=127.0.0.1
```

For production reverse proxy patterns, see [`docs/reverse-proxy.md`](https://github.com/swissmakers/fail2ban-ui/blob/main/docs/reverse-proxy.md).

## HTTP base path (for subpath deployment)

- `BASE_PATH`
  Optional URL path prefix where the application is served (environment-only, not configurable in the UI).
  Examples: unset or empty = `/`; if set to `/myf2b`, UI, static files, API, WebSocket, and OIDC routes will be reachable under `https://host/myf2b/...`.

Rules:

- Use a single leading slash and no trailing slash (e.g. `/myf2b`, not `myf2b/`).
- When set, the app is served under that prefix. Visiting `/` redirects to `{BASE_PATH}/`, and non-prefixed paths are not served.
- The reverse proxy must forward requests **with this path prefix** to Fail2Ban UI (see [`docs/reverse-proxy.md`](https://github.com/swissmakers/fail2ban-ui/blob/main/docs/reverse-proxy.md)).

When `BASE_PATH` is set, you must align related URLs:

- **`CALLBACK_URL`**: public base including the path, e.g. `https://fail2ban.example.com/myf2b` (no trailing slash).
- **`OIDC_REDIRECT_URL`**: must include the path, e.g. `https://fail2ban.example.com/myf2b/auth/callback`.

## Callback URL and secret (Fail2Ban -> UI)

Fail2Ban UI receives ban/unban callbacks at:

- `POST {BASE_PATH}/api/ban` (or `POST /api/ban` as default)
- `POST {BASE_PATH}/api/unban` (or `POST /api/unban` as default)

Required environment variables:

- `CALLBACK_URL`  
  URL reachable from managed Fail2Ban hosts (scheme + host + optional port + **`BASE_PATH`** if used). No trailing slash.
- `CALLBACK_SECRET`  
  Shared secret validated via `X-Callback-Secret` header.  
  If not set, Fail2Ban UI generates a secret on first start.

Example:

```bash
-e CALLBACK_URL=http://10.88.0.1:3080 \
-e CALLBACK_SECRET='replace-with-a-random-secret'
```

With a subpath:

```bash
-e BASE_PATH=/myf2b \
-e CALLBACK_URL=https://fail2ban.example.com/myf2b \
-e CALLBACK_SECRET='replace-with-a-random-secret'
```

## Privacy and telemetry controls

- `DISABLE_EXTERNAL_IP_LOOKUP=true`  
  Disables external public-IP lookup used in UI display.
- `UPDATE_CHECK=false`  
  Disables GitHub release update checks.

## UI behavior flags

- `AUTODARK=false` (default)  
  Enables automatic dark mode based on browser/OS preference only when `true`.  
  Default behavior remains light mode.

## Fail2Ban configuration migration

- `JAIL_AUTOMIGRATION=true`  
  EXPERIMENTAL migration from monolithic `jail.local` to `jail.d/*.local`.  
  Recommended: migrate manually on production systems.

## Alert settings (UI-managed)

Configure in **Settings -> Alert Settings**:

- Provider: `email` | `webhook` | `elasticsearch`
- Enable alerts for bans/unbans
- Alert country filters
- GeoIP provider and log-line limits

Detailed provider behavior and payloads:

- [`docs/alert-providers.md`](https://github.com/swissmakers/fail2ban-ui/blob/main/docs/alert-providers.md)
- [`docs/webhooks.md`](https://github.com/swissmakers/fail2ban-ui/blob/main/docs/webhooks.md)

## Threat intelligence settings (UI-managed)

Configure in **Settings -> Alert Settings**:

- `threatIntel.provider`: `none` | `alienvault` | `abuseipdb`
- `threatIntel.alienVaultApiKey` (for `alienvault`)
- `threatIntel.abuseIpDbApiKey` (for `abuseipdb`)

Runtime notes:

- Queries are executed server-side via `GET /api/threat-intel/:ip`
- Successful responses are cached for 30 minutes (provider+IP)
- Upstream `429` triggers retry-window/backoff with stale-cache fallback

See [`docs/threat-intel.md`](https://github.com/swissmakers/fail2ban-ui/blob/main/docs/threat-intel.md) for full details.

## OIDC authentication

Required when enabled:

- `OIDC_ENABLED=true`
- `OIDC_PROVIDER=keycloak|authentik|pocketid`
- `OIDC_ISSUER_URL=...`
- `OIDC_CLIENT_ID=...`
- `OIDC_CLIENT_SECRET=...`
- `OIDC_REDIRECT_URL=https://<ui-host>{BASE_PATH}/auth/callback`
  Example with `BASE_PATH=/myf2b`: `https://<ui-host>/myf2b/auth/callback`

Common optional variables:

- `OIDC_SCOPES=openid,profile,email`
- `OIDC_SESSION_SECRET=<32+ bytes recommended>`
- `OIDC_SESSION_MAX_AGE=3600`
- `OIDC_USERNAME_CLAIM=preferred_username`
- `OIDC_SKIP_VERIFY=false` (development only)
- `OIDC_SKIP_LOGINPAGE=false`

Provider notes:

- Keycloak: allow redirect URI `{BASE_PATH}/auth/callback` (or `/auth/callback` at root) and post-logout redirect `{BASE_PATH}/auth/login`
- Authentik/Pocket-ID: redirect URI must match exactly (including any `BASE_PATH` prefix)

Related:

- OIDC dev stack: `development/oidc/README.md`

## Email template style

- `emailStyle=classic`  
  Uses the classic email template instead of the default modern template (Email provider only).