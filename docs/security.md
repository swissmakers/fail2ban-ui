# Security guidance

This project can perform security-sensitive operations (bans, configuration changes). Deploy it as you would deploy every other administrative interface.

## Recommended deployment posture

- Do not expose the UI directly to the Internet.
- Prefer one of:
  - VPN-only access
  - Reverse proxy with strict allowlists
  - OIDC enabled (in addition to network controls)

If you must publish it, put it behind TLS and an authentication layer, and restrict source IPs.

## Input validation

All user-supplied IP addresses are validated using Go's `net.ParseIP` and `net.ParseCIDR` before they are passed to any integration, command, or database query. This applies to:

- Ban/Unban callbacks (`/api/ban`, `/api/unban`)
- Manual ban/unban actions from the dashboard
- Advanced action test endpoint (`/api/advanced-actions/test`)
- All integration connectors (MikroTik, pfSense, OPNsense)

Integration-specific identifiers (address list names, alias names) are validated against a strict alphanumeric pattern (`[a-zA-Z0-9._-]`) to prevent injection in both SSH commands and API payloads.

## WebSocket security

The WebSocket endpoint (`/api/ws`) is protected by:

- **Origin validation**: The upgrade handshake verifies that the `Origin` header matches the request's `Host` header (same-origin policy). Cross-origin WebSocket connections are rejected. This prevents cross-site WebSocket hijacking attacks.
- **Authentication**: When OIDC is enabled, the WebSocket endpoint requires a valid session.

## Callback endpoint protection

The fail2ban callback endpoints (`/api/ban`, `/api/unban`) are only reachable with a correct `CALLBACK_SECRET`. This secret must be atleast 20 characters long. If not specified a secure secret, will be automatically genereated on first start. It can be further protected by:

- Use even a stronger `CALLBACK_SECRET` than our default (32 characters)
- Make network restrictions (only allow known Fail2Ban hosts to reach the callback endpoint)

Rotate the secret if you suspect leakage.

## SSH connector hardening

For SSH-managed hosts:

- Use a dedicated service account (not a human user).
- Require key-based auth.
- Restrict sudo to the minimum set of commands required to operate Fail2Ban (typically `fail2ban-client` and optionally `systemctl restart fail2ban`).
- Use filesystem ACLs for `/etc/fail2ban` rather than broad permissions to allow full modification capabilities for the specific user.

## Integration connector hardening

When using external firewall integrations (MikroTik, pfSense, OPNsense):

- Use a dedicated service account on the firewall device with the minimum permissions needed (address-list management only on MikroTik; alias management only on pfSense/OPNsense).
- For pfSense/OPNsense: use a dedicated API token with limited scope.
- Restrict network access so the Fail2ban-UI host is the only source allowed to reach the firewall management interface.

## Least privilege and file access

Local connector deployments typically require access to:
- `/var/run/fail2ban/fail2ban.sock`
- `/etc/fail2ban/`
- selected log paths (read-only, mounted to same place inside the container, where they are on the host.)

Avoid running with more privileges than necessary. If you run in a container, use the repository deployment guide and SELinux policies.

## SELinux

If SELinux is enabled, use the policies provided in (according to your specific setup they are not enough):
- `deployment/container/SELinux/`

Do not disable SELinux as a shortcut. Fix always labeling and policy issues instead. -> Everytime you read "to disable SELinux" you can close that guide :)

## Audit and operational practices

- Back up `/config` (DB + settings) regularly.
- Treat the database as sensitive operational data.
- Keep the host and container runtime patched.
- Review Fail2Ban actions deployed to managed hosts as part of change control.