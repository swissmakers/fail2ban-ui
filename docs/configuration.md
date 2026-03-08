# Configuration reference

This document describes common runtime settings. Some values are stored in the database via the UI; environment variables take precedence where noted.

## Network settings

- `PORT`  
  TCP port for the HTTP server (default: 8080).

- `BIND_ADDRESS`  
  Bind address for the HTTP server (default: `0.0.0.0`). Use `127.0.0.1` if you only publish through a reverse proxy on the same host.

Example:
```bash
-e PORT=3080 -e BIND_ADDRESS=127.0.0.1
````

## Callback URL and secret (Fail2Ban -> UI)

Fail2Ban UI receives ban/unban callbacks at:

* `POST /api/ban`
* `POST /api/unban`

The callback action on each managed Fail2Ban host must be able to reach the UI callback URL.

* `CALLBACK_URL`
  The external URL that Fail2Ban hosts use for callbacks.
  Default behavior typically matches `http://127.0.0.1:<PORT>` (works for same-host deployments).

* `CALLBACK_SECRET`
  Shared secret for authenticating callbacks. If not set, the UI generates one on first start.
  Recommended: set a fixed secret in production and keep it private.

Example (container bridge / remote hosts):

```bash
-e CALLBACK_URL=http://10.88.0.1:3080 \
-e CALLBACK_SECRET='replace-with-a-random-secret'
```

Callbacks must include:

* Header `X-Callback-Secret: <secret>`

## Privacy-related settings

* `DISABLE_EXTERNAL_IP_LOOKUP=true`
  Disables any external lookup used to display the host’s public IP address in the UI.

* `UPDATE_CHECK=false`
  Disables checking GitHub for a newer release.

## Fail2Ban config migration

* `JAIL_AUTOMIGRATION=true`
  Experimental: attempts to migrate a monolithic `jail.local` into `jail.d/`.
  Recommended: migrate manually on production systems.

## Email template selection

* `emailStyle=classic`
  Switches back alert emails from the modern template to the classic template (only applies when the Email alert provider is selected).

## Alert providers

Alert settings are configured through the UI (Settings → Alert Settings). Three providers are available:

| Provider | Description |
|---|---|
| Email (SMTP) | Default. Sends HTML-formatted alert emails via SMTP. |
| Webhook | Sends JSON payloads to any HTTP endpoint (ntfy, Matrix, Slack, Gotify, custom APIs). |
| Elasticsearch | Indexes events as ECS-compatible documents into Elasticsearch for Kibana analysis. |

All providers share the same global settings:
- Enable/disable alerts for bans and unbans independently
- Country-based alert filtering (only alert on selected countries)
- GeoIP provider selection (built-in API or local MaxMind database)
- Maximum log lines included in alert payloads

Provider-specific settings (SMTP credentials, webhook URL/headers, Elasticsearch URL/auth) are configured in the same UI section and stored in the database.

For full provider documentation, setup hints, payload formats, and examples, see [`docs/alert-providers.md`](https://github.com/swissmakers/fail2ban-ui/blob/main/docs/alert-providers.md).

## Threat intelligence

Threat intelligence settings are configured through the UI (Settings -> Alert Settings):

- `threatIntel.provider`: `none` | `alienvault` | `abuseipdb`
- `threatIntel.alienVaultApiKey`: required when provider is `alienvault`
- `threatIntel.abuseIpDbApiKey`: required when provider is `abuseipdb`

Runtime behavior:
- Lookups are performed through the backend endpoint `GET /api/threat-intel/:ip`.
- Successful results are cached per provider+IP for 30 minutes. (currently in-memory only -> if a modal is reopened multible times..)
- Upstream 429 responses trigger retry-window handling and stale-cache fallback (if available).

For full details (setup, response model, cache/rate-limit behavior, and troubleshooting), see [`docs/threat-intel.md`](https://github.com/swissmakers/fail2ban-ui/blob/main/docs/threat-intel.md).

## OIDC authentication

OIDC can protect the UI with an external identity provider.

Required:

* `OIDC_ENABLED=true`
* `OIDC_PROVIDER=keycloak|authentik|pocketid`
* `OIDC_ISSUER_URL=...`
* `OIDC_CLIENT_ID=...`
* `OIDC_CLIENT_SECRET=...`
* `OIDC_REDIRECT_URL=https://<ui-host>/auth/callback`

Optional (common):

* `OIDC_SCOPES=openid,profile,email`
* `OIDC_SESSION_SECRET=<32+ bytes recommended>` (random is generated if omitted)
* `OIDC_SESSION_MAX_AGE=3600`
* `OIDC_USERNAME_CLAIM=preferred_username`
* `OIDC_SKIP_VERIFY=false` (development only)
* `OIDC_SKIP_LOGINPAGE=false`

Provider notes:

* Keycloak: ensure your client allows the redirect URI (`/auth/callback`) and post-logout redirect (`/auth/login`).
* Authentik/Pocket-ID: follow their OIDC client configuration and match the redirect URI exactly.

Additional resources:

* OIDC dev environment: `development/oidc/README.md`