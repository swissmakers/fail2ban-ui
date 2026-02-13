# Troubleshooting

## UI not reachable

Check:
- Container/service is running
- Host firewall allows the configured port
- Reverse proxy forwards correctly (if used)
- Firewalld port allowed?

Examples:
```bash
podman ps
podman logs fail2ban-ui

# systemd:
systemctl status fail2ban-ui
journalctl -u fail2ban-ui -f

# firewalld:
firewall-cmd --list-all
firewall-cmd --add-port=8080/tcp --permanent
firewall-cmd --reload
````

## Local connector fails

Check:

* Fail2Ban is running and socket exists
* Container has the socket mounted
* Permissions allow access to the socket
* SELinux problems

Examples:

```bash
systemctl status fail2ban
ls -la /var/run/fail2ban/fail2ban.sock
fail2ban-client status

# check the socked in the container:
podman exec -it fail2ban-ui ls -la /var/run/fail2ban/fail2ban.sock

# SELinux check for alerts (needs "setroubleshoot" linux package):
sealert -a /var/log/audit/audit.log
```

## SSH connector fails

Check:

* Key-based SSH works outside the UI
* Service account exists and has required sudo / facl permissions
* ACLs also allow modifications under `/etc/fail2ban`

Examples:

```bash
ssh -i ~/.ssh/<key> <user>@<host>
sudo -l -U <user>
getfacl /etc/fail2ban

# Connect manually from the fail2ban-UI connector to the remote host: (this example uses the "development/ssh_and_local" dev stack)
sudo podman exec -it fail2ban-ui ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -i /config/.ssh/id_rsa -p 2222 testuser@127.0.0.1
```

## Bans fail due to firewall backend (nftables / firewalld)

Symptoms often mention `iptables (nf_tables)` or action startup errors.

Fix:

* Use Fail2Ban banactions matching your host firewall backend:

  * firewalld (use on Rocky / Red Hat / Almalinux): `firewallcmd-rich-rules`, `firewallcmd-allports`
  * nftables: `nftables-multiport`, `nftables-allports`
  * legacy iptables: `iptables-multiport`, `iptables-allports`

## OIDC login problems

Check:

* Issuer URL is correct and reachable
* Redirect URI matches exactly: `https://<host>/auth/callback`
* Provider client configuration includes post-logout redirect to `https://<host>/auth/login`

Logs:

```bash
podman logs fail2ban-ui
# Also enable debug logging over env or over the webUI
```

## Database issues

Check:

* `/config` is writable by the container/service user
* SQLite file permissions are correct

Example:

```bash
ls -la /opt/fail2ban-ui
sqlite3 /opt/fail2ban-ui/fail2ban-ui.db "PRAGMA integrity_check;"