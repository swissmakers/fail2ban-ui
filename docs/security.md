# Security guidance

This project can perform security-sensitive operations (bans, configuration changes). Deploy it as you would deploy every other administrative interface.

## Recommended deployment posture

- Do not expose the UI directly to the Internet.
- Prefer one of:
  - VPN-only access
  - Reverse proxy with strict allowlists
  - OIDC enabled (in addition to network controls)

If you must publish it, put it behind TLS and an authentication layer, and restrict source IPs.

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