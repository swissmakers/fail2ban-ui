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
  Switches back alert emails from the modern template to the classic template.

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