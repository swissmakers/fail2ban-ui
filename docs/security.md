# Security guidance

Fail2Ban UI performs security-sensitive operations: it bans addresses, changes firewall state, and edits Fail2Ban configuration on managed hosts. Deploy it as you would deploy any other administrative interface.

## Recommended deployment posture

* Do not expose the UI directly to the Internet.
* Prefer one of:
  * VPN-only access
  * A reverse proxy with strict source allowlists
  * OIDC enabled, in addition to network controls
* If you must publish it, put it behind TLS and an authentication layer, and restrict source IPs.

See [reverse-proxy.md](reverse-proxy.md) for hardened proxy examples and the WebSocket forwarding requirements.

## Authentication model

Sessions are stateless encrypted cookies (AES-GCM), logout clears the cookie but cannot revoke an already-captured session token before its expiry (`OIDC_SESSION_MAX_AGE`, default 1 hour). Keep session lifetimes short and always serve the UI over TLS.

When OIDC role-based access control is configured (`OIDC_ADMIN_ROLES` / `OIDC_SUPPORT_ROLES`), the user's roles and access level are captured at login and stored in the session cookie. Role changes at the identity provider only take effect after the user logs in again — another reason to keep session lifetimes short. Users whose roles match neither list can authenticate but are denied on every API endpoint.

The debug console (Settings → Console Output) mirrors the complete server log to every connected UI client over the WebSocket. Log lines can include client IPs, email addresses, and configuration diagnostics — leave it disabled unless actively debugging.

## Input validation

All user-supplied IP addresses are validated with Go's `net.ParseIP` and `net.ParseCIDR` before they reach any integration, command, or database query. This applies to:

* Ban/unban callbacks (`/api/ban`, `/api/unban`)
* Manual ban and unban actions from the dashboard
* The advanced-actions test endpoint (`/api/advanced-actions/test`)
* All integration connectors (MikroTik, pfSense, OPNsense)

Integration-specific identifiers, such as address-list and alias names, are validated against a strict alphanumeric pattern (`[a-zA-Z0-9._-]`) to prevent injection in SSH commands and API payloads.

## WebSocket security

The WebSocket endpoint (`/api/ws`) is protected by:

* **Origin validation.** The upgrade handshake verifies that the `Origin` header matches the request's `Host` header (same-origin policy). Cross-origin WebSocket connections are rejected, which prevents cross-site WebSocket hijacking.
* **Authentication.** When OIDC is enabled, the endpoint requires a valid session.

## Callback endpoint protection

The callback endpoints (`/api/ban`, `/api/unban`) are protected by `CALLBACK_SECRET`, transmitted in the `X-Callback-Secret` header. If no secret is configured, Fail2Ban UI generates one on first start.

Additional hardening:

* Use a long, random secret and rotate it on suspected leakage.
* Restrict network access so that only the managed Fail2Ban hosts can reach the callback endpoints.
* Serve the callback URL over `https://` with a certificate the managed hosts trust. The generated ban action verifies TLS certificates by default; `CALLBACK_INSECURE_TLS=true` disables verification and should only be used with self-signed certificates on trusted networks (see [configuration.md](configuration.md)).

## Secrets at rest

Secrets (callback secret, SMTP password, agent tokens, integration API keys) are stored in the SQLite database and embedded in the generated `action.d/ui-custom-action.conf`. Fail2Ban UI restricts both to file mode `0600` on startup. Read APIs never return stored secrets; the frontend receives a placeholder sentinel and unchanged saves keep the stored value.

## SSH connector hardening

For SSH-managed hosts:

* Use a dedicated service account, not a human user.
* Require key-based authentication.
* Restrict sudo to the minimum command set needed to operate Fail2Ban - at minimum `fail2ban-client *` and `systemctl restart fail2ban`.
* Grant write access to `/etc/fail2ban` through filesystem ACLs for that specific account, rather than through broad directory permissions.

## Integration connector hardening

When using the firewall integrations (MikroTik, pfSense, OPNsense):

* Use a dedicated service account on the firewall device with the minimum permissions needed: address-list management only on MikroTik; alias management only on pfSense and OPNsense.
* For pfSense and OPNsense, use a dedicated API token with limited scope.
* Restrict network access so the Fail2Ban UI host is the only source allowed to reach the firewall management interface.
* Configure the MikroTik SSH host-key fingerprint. When no fingerprint is set, the connector accepts any host key (MITM exposure); with one configured, it is verified with a constant-time comparison.

## Least privilege and file access

Local-connector deployments typically require access to:

* `/var/run/fail2ban/fail2ban.sock`
* `/etc/fail2ban/`
* Selected log paths, read-only, mounted at the same paths inside the container as on the host

Avoid running with more privileges than necessary. In a container, follow the [container deployment guide](../deployment/container/README.md) and, where needed, the optional SELinux modules.

## SELinux

Do not disable SELinux as a shortcut. Fix labeling, booleans, and policy issues instead.

### Fail2Ban callbacks: `curl` from `fail2ban_t`

The UI installs an action that runs `curl` from the Fail2Ban service context to reach `/api/ban` and `/api/unban`. With SELinux enforcing, you may see denials such as `curl` / `fail2ban_t` / `name_connect` / `tcp_socket` / `http_port_t` - for example when the callback URL uses HTTPS on port 443.

On RHEL-family systems, `setroubleshoot` typically recommends the `nis_enabled` boolean, which allows this class of outbound connection:

```bash
sudo setsebool -P nis_enabled 1
```

Prefer the distribution boolean over ad-hoc `audit2allow` modules, unless your organization requires a different control.

### Container to host Fail2Ban (optional modules)

If the UI runs in Podman or Docker with a *local* connector, additional rules can be needed so that `container_t` can use the Fail2Ban socket and read the expected logs. This is a different problem from the callback boolean above. Sources and build steps are in [deployment/container/SELinux/](../deployment/container/SELinux/).

## Alert provider security

Fail2Ban UI supports three alert providers: Email (SMTP), Webhook, and Elasticsearch.

### Email (SMTP)

* Enable TLS (**Use TLS**) for all SMTP connections.
* Do not disable certificate validation (**Skip TLS Verification**) in production. If you must, ensure the network path to the SMTP server is trusted.
* Where supported (Gmail, Office365), use application-specific passwords or OAuth tokens instead of primary account passwords.

### Webhook

* Use HTTPS endpoints whenever possible.
* If the endpoint requires authentication, pass it in custom headers (for example `Authorization: Bearer <token>`) rather than embedding credentials in the URL.
* The **Skip TLS Verification** option exists for development and self-signed environments only.

### Elasticsearch

* Prefer API-key authentication over basic auth. API keys can be scoped to specific indices and rotated independently.
* Restrict the API key to write-only access on the `fail2ban-events-*` index pattern. Avoid cluster-wide or admin-level keys.
* Use Elasticsearch role-based access control to limit what the Fail2Ban UI service account can do.

## Audit and operational practices

* Back up `/config` (database and settings) regularly.
* Treat the database as sensitive operational data.
* Keep the host and the container runtime patched.
* Review the Fail2Ban actions deployed to managed hosts as part of your change control.
