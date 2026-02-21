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

## Ban/unban notifications not showing up in the UI

This is one of the most common issues. The UI receives ban/unban events from Fail2Ban via HTTP callbacks. If nothing appears in the dashboard or "Recent stored events", the callback chain is broken somewhere. Follow these steps systematically.

### Step 1: Verify the action file exists and is correct

Fail2ban-UI creates a custom action file at `/etc/fail2ban/action.d/ui-custom-action.conf` on each managed host. This file contains `curl` commands that notify the UI when bans/unbans happen.

```bash
# Check if the action file exists:
cat /etc/fail2ban/action.d/ui-custom-action.conf

# You should see actionban and actionunban sections with curl commands pointing
# to your Fail2ban-UI callback URL (e.g. http://10.88.0.1:8080/api/ban)
```

If the file does not exist or looks wrong, go to Settings → Manage Servers in the UI, select the server, and click "Test connection". The UI will re-deploy the action file automatically for local connectors.

### Step 2: Verify jail.local references the action

Fail2ban-UI writes a `jail.local` that uses the custom action. Check that it is in place:

```bash
cat /etc/fail2ban/jail.local | head -30

# Look for the lines like:
# action = %(action_mwlg)s
# and a definition of action_mwlg that references ui-custom-action
```

If your `jail.local` was created manually or by another tool, the `ui-custom-action` might not be referenced. The easiest fix: let the UI manage `jail.local` by removing your manual version and restarting from the UI.

### Step 3: Check network connectivity from Fail2Ban host to the UI

The `curl` command in the action file must be able to reach the UI's callback URL. Test this from the Fail2Ban host (or from inside the container if Fail2Ban runs in one):

```bash
# Replace with your actual Fail2ban-UI address:
curl -s -o /dev/null -w "%{http_code}" http://10.88.0.1:8080/api/version

# Expected: 200
# If you get connection refused, timeout, or another error,
# fix network/firewall rules first.
```

Common issues:
- Container using bridge networking but callback URL points to `127.0.0.1` (use the host IP or `--network=host`)
- Firewall on the UI host blocks the port

### Step 4: Verify the callback secret

Every callback must include the header `X-Callback-Secret`. The value must match what the UI expects. You can find the current secret in Settings → General Settings → Callback Secret (or check the container environment).

```bash
# Check what secret the action file uses:
grep "X-Callback-Secret" /etc/fail2ban/action.d/ui-custom-action.conf

# Compare with the UI's expected secret (from the settings page or env var)
```

If they do not match, re-deploy the action file via "Test connection" from the UI, or manually update the secret in the action file and restart Fail2Ban.

### Step 5: Simulate a ban notification with curl

This is the most direct way to test the full callback chain. Run this from any host that can reach the UI:

```bash
FAIL2BAN_UI_HOST="your_fail2ban_host"
SECRET="your_secret"

curl -v -X POST http://$FAIL2BAN_UI_HOST:8080/api/ban \
  -H "Content-Type: application/json" \
  -H "X-Callback-Secret: $SECRET" \
  -d '{
    "serverId": "local",
    "ip": "203.0.113.42",
    "jail": "sshd",
    "hostname": "testhost",
    "failures": "5",
    "logs": "Jun 15 12:00:00 testhost sshd: Failed password for root from 203.0.113.42"
  }'
```

Expected response:
```json
{"message":"Ban notification processed successfully"}
```

If it works, you should immediately see:
- A new entry in "Recent stored events" on the dashboard
- A real-time WebSocket update (the entry appears without refreshing)

Common error responses:
- `401 Unauthorized` with `"Callback secret not configured"` → Secret not set in UI settings
- `401 Unauthorized` with `"Invalid callback secret"` → Secret mismatch
- `400 Bad Request` with `"invalid IP"` → The IP address in the payload is malformed
- `400 Bad Request` with `"Invalid request"` → JSON parsing failed (check `ip` and `jail` fields are present)

To simulate an unban:

```bash
curl -v -X POST http://$FAIL2BAN_UI_HOST:8080/api/unban \
  -H "Content-Type: application/json" \
  -H "X-Callback-Secret: $SECRET" \
  -d '{
    "serverId": "local",
    "ip": "203.0.113.42",
    "jail": "sshd",
    "hostname": "testhost"
  }'
```

### Step 6: Check what Fail2Ban is actually sending

If the curl test above works but real bans still don't show up, Fail2Ban itself might not be executing the action correctly. Check:

```bash
# Trigger a real ban (use a test jail or ban a test IP):
fail2ban-client set sshd banip 198.51.100.1

# Watch the Fail2Ban log for errors:
tail -f /var/log/fail2ban.log

# Look for lines like:
#   ERROR   ... Action ... failed
#   WARNING ... Command ... failed
```

You can also manually run the exact `curl` command from the action file to see what happens. Extract it from the action file and run it in your shell (replace the Fail2Ban variables like `<ip>`, `<name>`, etc. with real values):

```bash
# Extract and run the actionban command manually:
grep -A5 "actionban" /etc/fail2ban/action.d/ui-custom-action.conf

# Then execute the curl command with real values substituted.
# This reveals whether jq is missing, curl has TLS issues, etc.
```

Common issues at this stage:
- **`jq` not installed**: The action file uses `jq` to build JSON. Install it: `dnf install jq` or `apt install jq`
- **TLS certificate issues**: If the callback URL uses HTTPS with a self-signed cert, the action file needs the `-k` flag (Fail2ban-UI adds this automatically when the callback URL starts with `https://`)
- **Fail2Ban not restarted**: After the action file is deployed, Fail2Ban must be restarted to pick up changes: `systemctl restart fail2ban`

### Step 7: Check the Fail2ban-UI logs

The UI logs every incoming callback with details. Check the container or service logs:

```bash
# Container:
podman logs -f fail2ban-ui

# systemd:
journalctl -u fail2ban-ui -f

# Look for lines like:
#   ✅ Parsed ban request - IP: ..., Jail: ...
#   ⚠️ Invalid callback secret ...
#   ❌ JSON parsing error ...
```

If you enabled debug mode in the UI settings, you will also see the raw JSON body of every incoming callback.

### Step 8: Verify the `serverId` resolves

The callback payload includes a `serverId`. The UI uses this to match the event to a configured server. If neither matches any known server, the UI will reject the callback.

Check that the `serverId` in the action file matches the server ID shown in Settings → Manage Servers. You can see the configured server IDs via:

```bash
curl -s http://$FAIL2BAN_UI_HOST:8080/api/servers \
  -H "X-F2B-Server: default" | jq '.servers[] | {id, name, hostname}'
```

### Quick reference: end-to-end callback flow

```
Fail2Ban detects intrusion
  → triggers actionban in ui-custom-action.conf
    → curl POST /api/ban with JSON payload + X-Callback-Secret header
      → Fail2ban-UI validates secret
        → Fail2ban-UI validates IP format
          → Fail2ban-UI resolves server (by serverId)
            → Stores event in SQLite (ban_events table)
              → Broadcasts via WebSocket to all connected browsers
                → Optional: sends email alert, evaluates advanced actions
```

If any step fails, the chain stops and the event will not appear in the UI.

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

## WebSocket not connecting

If the real-time dashboard updates (ban/unban events appearing without page refresh) are not working:

Check:

* Browser console for WebSocket errors (F12 → Console tab)
* The WebSocket status indicator in the UI footer
* If using a reverse proxy, ensure it supports WebSocket upgrades

Common issues:

* **Reverse proxy not forwarding WebSocket**: Nginx requires explicit WebSocket upgrade configuration:
  ```nginx
  location /api/ws {
      proxy_pass http://127.0.0.1:8080;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
  }
  ```

* **Origin mismatch**: The WebSocket endpoint validates that the `Origin` header matches the `Host` header. If your reverse proxy rewrites the `Host` header but not the `Origin`, the connection will be rejected. Ensure both headers are consistent.

* **OIDC session expired**: When OIDC is enabled, the WebSocket requires a valid session. If the session expires, the WebSocket connection will fail with a 302 redirect or 401 error. Re-login to the UI to fix this.

## Database issues

Check:

* `/config` is writable by the container/service user
* SQLite file permissions are correct

Example:

```bash
ls -la /opt/fail2ban-ui
sqlite3 /opt/fail2ban-ui/fail2ban-ui.db "PRAGMA integrity_check;"