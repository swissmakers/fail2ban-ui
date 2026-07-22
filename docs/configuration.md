# Configuration reference

This document describes the runtime settings and related operational behavior. Most options are configured in the UI and stored in the database; environment variables override behavior where applicable.

## Network and listener settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `BIND_ADDRESS` | `0.0.0.0` | Listen address. Use `127.0.0.1` when a local reverse proxy fronts the UI. |

Example:

```bash
-e PORT=3080 -e BIND_ADDRESS=127.0.0.1
```

For production reverse proxy patterns, see [reverse-proxy.md](reverse-proxy.md).

## HTTP base path (subpath deployment)

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_PATH` | unset (`/`) | Optional URL path prefix under which the application is served. Environment-only; not configurable in the UI. |

With `BASE_PATH=/myf2b`, the UI, static files, API, WebSocket, and OIDC routes are reachable under `https://host/myf2b/...`.

Rules:

* Use a single leading slash and no trailing slash: `/myf2b`, not `myf2b/`.
* When set, the application is served only under that prefix. Visiting `/` redirects to `{BASE_PATH}/`; non-prefixed paths are not served.
* The reverse proxy must forward requests *with* the path prefix to Fail2Ban UI. See [reverse-proxy.md](reverse-proxy.md).

When `BASE_PATH` is set, align the related URLs:

* `CALLBACK_URL` must include the prefix, for example `https://fail2ban.example.com/myf2b` (no trailing slash).
* `OIDC_REDIRECT_URL` must include the prefix, for example `https://fail2ban.example.com/myf2b/auth/callback`.

## Callback URL and secret (Fail2Ban to Fail2ban-UI)

Fail2Ban UI receives ban and unban callbacks at:

* `POST {BASE_PATH}/api/ban` (`POST /api/ban` by default)
* `POST {BASE_PATH}/api/unban` (`POST /api/unban` by default)

| Variable | Description |
|----------|-------------|
| `CALLBACK_URL` | URL reachable from every managed Fail2Ban host: scheme, host, optional port, and `BASE_PATH` if used. No trailing slash. |
| `CALLBACK_SECRET` | Shared secret validated through the `X-Callback-Secret` header. If unset, Fail2Ban UI generates one on first start. |
| `CALLBACK_INSECURE_TLS` | Default `false`. When `true` (or `1`/`yes`/`on`), the `curl` command in the generated ban action skips TLS certificate verification (`-k`) for an `https://` callback URL. Only enable this if the UI uses a self-signed certificate that the managed hosts do not trust. |

> **Upgrade note:** older releases always passed `-k` for `https://` callback URLs. TLS verification is now on by default because the callback carries the shared secret. If your UI runs with a self-signed certificate, either install the certificate on every managed host or set `CALLBACK_INSECURE_TLS=true`, otherwise ban callbacks will fail silently after upgrading. The regenerated action file is pushed to managed hosts automatically at startup.

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

### Reverse SSH tunnel for callbacks

SSH-connected servers can enable **reverse tunnel for events** (server form). The UI then opens a reverse tunnel (`ssh -R <port>:localhost:<port>`) alongside the SSH control connection so callbacks reach the UI even when the managed host cannot connect to it directly (NAT, firewall). The port is derived from `CALLBACK_URL` (explicit port, otherwise 443/80 by scheme).

The tunnel is only used if `CALLBACK_URL` points to `localhost`/`127.0.0.1` — the remote Fail2Ban sends its callbacks to that URL, which the tunnel forwards to the UI. With a public callback URL the callbacks bypass the tunnel; the UI logs a warning in that case. Note that a localhost callback URL applies globally, so mixing tunneled and non-tunneled remote servers is not possible.

## Privacy and telemetry controls

| Variable | Description |
|----------|-------------|
| `DISABLE_EXTERNAL_IP_LOOKUP=true` | Disables the external public-IP lookup used for display in the UI |
| `UPDATE_CHECK=false` | Disables the GitHub release update check |

## UI behavior flags

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTODARK` | `false` | When `true`, enables automatic dark mode based on the browser or OS preference. The default remains light mode. |

## Fail2Ban configuration migration

| Variable | Description |
|----------|-------------|
| `JAIL_AUTOMIGRATION=true` | Experimental migration from a monolithic `jail.local` to `jail.d/*.local`. On production systems, migrate manually instead. |

## Global Fail2Ban defaults (UI-managed)

Configure under **Settings → Global Settings**. These values are written to the `[DEFAULT]` section of the managed `jail.local` and pushed to every managed host:

* `bantime`, `findtime`, `maxretry`, `ignoreip`, `banaction` / `banaction_allports`, firewall `chain`
* Bantime increment escalation (optional, only emitted when set):
  * `bantime.rndtime` — random jitter added to escalating bans
  * `bantime.maxtime` — cap for escalating bans (e.g. `5w`)
  * `bantime.factor` — escalation multiplier (Fail2Ban default: `1`)
  * `bantime.overalljails` — count repeat offenses across all jails instead of per jail

Duration fields accept plain seconds or Fail2Ban time suffixes (`3600`, `48h`, `5w`, `1d 12h`). `bantime` additionally accepts `-1` for permanent bans.

## Alert settings (UI-managed)

Configure under **Settings → Alert Settings**:

* Provider: `email`, `webhook`, or `elasticsearch`
* Enable alerts for bans and/or unbans
* Alert country filters
* GeoIP provider and log-line limits

> **Privacy note on the `builtin` GeoIP provider:** it resolves countries via the free ip-api.com service, which means every enriched (banned) IP address is sent to a third party — and the free tier only supports plain HTTP, so the queries travel unencrypted. For privacy-sensitive deployments use the MaxMind provider with a local GeoLite2 database instead.

For provider behavior and payloads, see [alert-providers.md](alert-providers.md) and [webhooks.md](webhooks.md).

## Threat intelligence settings (UI-managed)

Configure under **Settings → Alert Settings**:

* `threatIntel.provider`: `none`, `alienvault`, or `abuseipdb`
* `threatIntel.alienVaultApiKey` (for `alienvault`)
* `threatIntel.abuseIpDbApiKey` (for `abuseipdb`)

Runtime behavior:

* Queries run server-side through `GET /api/threat-intel/:ip`.
* Successful responses are cached for 30 minutes per provider and IP.
* An upstream `429` triggers a retry window with backoff and stale-cache fallback.

See [threat-intel.md](threat-intel.md) for details.

## OIDC authentication

Required when OIDC is enabled:

| Variable | Description |
|----------|-------------|
| `OIDC_ENABLED=true` | Enables OIDC authentication |
| `OIDC_PROVIDER` | `keycloak`, `authentik`, or `pocketid` |
| `OIDC_ISSUER_URL` | Issuer URL; must match the provider's discovery document |
| `OIDC_CLIENT_ID` | Client ID configured at the provider |
| `OIDC_CLIENT_SECRET` | Client secret |
| `OIDC_REDIRECT_URL` | `https://<ui-host>{BASE_PATH}/auth/callback`, for example `https://<ui-host>/myf2b/auth/callback` with `BASE_PATH=/myf2b` |

Common optional variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_SCOPES` | `openid,profile,email` | Requested scopes, comma-separated |
| `OIDC_SESSION_SECRET` | auto-generated | Session signing secret; 32 or more bytes recommended |
| `OIDC_SESSION_MAX_AGE` | `3600` | Session lifetime in seconds |
| `OIDC_USERNAME_CLAIM` | `preferred_username` | Claim used as the display username |
| `OIDC_SKIP_VERIFY` | `false` | Skips TLS verification toward the provider. Development only. |
| `OIDC_SKIP_LOGINPAGE` | `false` | Skips the UI login page and redirects to the provider directly |

OIDC role-based access control is optional. When no role variables are set, every authenticated OIDC user keeps the previous full-access behavior.

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_ROLE_CLAIM` | `groups` | Claim containing roles/groups. Dot paths are supported, for example `realm_access.roles` for Keycloak. |
| `OIDC_ADMIN_ROLES` | empty | Comma-separated OIDC role/group names that grant full admin access. |
| `OIDC_SUPPORT_ROLES` | empty | Comma-separated OIDC role/group names that grant support access: dashboard/event reads plus manual ban/unban. |

Provider notes:

* **Keycloak**: allow the redirect URI `{BASE_PATH}/auth/callback` (or `/auth/callback` at root) and the post-logout redirect `{BASE_PATH}/auth/login`.
* **Authentik / Pocket-ID**: the redirect URI must match exactly, including any `BASE_PATH` prefix.

A ready-to-run OIDC test environment is available under [development/oidc/README.md](../development/oidc/README.md).

## Email template style

| Variable | Description |
|----------|-------------|
| `emailStyle=classic` | Uses the classic email template instead of the default modern template (Email provider only) |
