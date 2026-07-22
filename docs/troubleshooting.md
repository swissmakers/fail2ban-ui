# Troubleshooting

## UI not reachable

Check:

* The container or service is running.
* The host firewall allows the configured port.
* The reverse proxy forwards correctly, if one is used.

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
```

## Local connector fails

Check:

* The `jq` package is installed on the host.
* Fail2Ban is running and the socket exists.
* The container has the socket mounted.
* Permissions allow access to the socket.
* SELinux is not denying access.

```bash
# RHEL / Rocky / AlmaLinux:
rpm -qa | grep jq

systemctl status fail2ban
ls -la /var/run/fail2ban/fail2ban.sock
fail2ban-client status

# Check the socket from inside the container:
podman exec -it fail2ban-ui ls -la /var/run/fail2ban/fail2ban.sock

# SELinux denial analysis (requires the setroubleshoot package):
sealert -a /var/log/audit/audit.log
```

## SSH connector fails

Check:

* Key-based SSH works outside the UI.
* The service account exists and has the required sudo and ACL permissions.
* The ACLs allow modifications under `/etc/fail2ban`.

```bash
ssh -i ~/.ssh/<key> <user>@<host>
sudo -l -U <user>
getfacl /etc/fail2ban

# Connect manually from the Fail2Ban UI container to the remote host
# (this example uses the development/ssh_and_local dev stack):
sudo podman exec -it fail2ban-ui ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
  -i /config/.ssh/id_rsa -p 2222 testuser@127.0.0.1
```

Recommended minimum sudoers for SSH connector accounts:

```bash
<user> ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client *
<user> ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart fail2ban
<user> ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload fail2ban
```

**Note:** Fail2Ban UI executes the Fail2Ban commands with `sudo` over SSH. The `NOPASSWD` option is therefore required.

## Ban/unban notifications do not appear in the UI

This is one of the most common issues. The UI receives ban and unban events from Fail2Ban through HTTP callbacks. If nothing appears on the dashboard or under "Recent stored events", the callback chain is broken somewhere. Work through the following steps in order.

### Step 1: Verify the action file exists and is correct

Fail2Ban UI creates a custom action file at `/etc/fail2ban/action.d/ui-custom-action.conf` on each managed host. It contains the `curl` commands that notify the UI on bans and unbans.

```bash
cat /etc/fail2ban/action.d/ui-custom-action.conf

# Expect actionban and actionunban sections with curl commands pointing
# to your callback URL, for example http://10.88.0.1:8080/api/ban
```

If the file does not exist or looks wrong, go to **Settings -> Manage Servers** in the UI, select the server, and click **Test connection**. The UI re-deploys the action file automatically for local connectors.

### Step 2: Verify jail.local references the action

Fail2Ban UI writes a `jail.local` that uses the custom action:

```bash
head -30 /etc/fail2ban/jail.local

# Look for lines such as:
#   action = %(action_mwlg)s
# and a definition of action_mwlg that references ui-custom-action
```

If `jail.local` was created manually or by another tool, `ui-custom-action` might not be referenced. The simplest fix is to let the UI manage `jail.local`: remove the manual version and restart from the UI.

### Step 3: Check connectivity from the Fail2Ban host to the UI

The `curl` command in the action file must reach the callback URL. Test from the Fail2Ban host (or from inside its container, if Fail2Ban runs in one):

```bash
# Replace with your actual Fail2Ban UI address:
curl -s -o /dev/null -w "%{http_code}" http://10.88.0.1:8080/api/version

# Expected: 200
# On connection refused, timeout, or another error, fix network/firewall rules first.
```

Common causes:

* A container on bridge networking with a callback URL pointing to `127.0.0.1`. Use the host IP, or `--network=host`.
* A firewall on the UI host blocking the port.

### SELinux: callbacks blocked (`curl` denied)

If bans work but events never reach the UI, and the audit log shows SELinux denying `curl` in domain `fail2ban_t` when connecting to an HTTP or HTTPS port (for example `name_connect` to `http_port_t` on 443), the Fail2Ban action cannot reach the callback URL.

On RHEL, Rocky Linux, AlmaLinux, and similar:

```bash
sudo setsebool -P nis_enabled 1
```

Then trigger a test ban and check `audit.log` or `sealert` again. This is the same remedy that `setroubleshoot` suggests for this denial pattern. If your policy team cannot use `nis_enabled`, they can craft an explicit allow rule. Do not turn SELinux off globally.

### Step 4: Verify the callback secret

Every callback must include the `X-Callback-Secret` header, and the value must match what the UI expects. The current secret is visible under **Settings -> General Settings -> Callback Secret** (with a show/hide toggle), or in the container environment.

```bash
# Secret used by the action file:
grep "X-Callback-Secret" /etc/fail2ban/action.d/ui-custom-action.conf

# Compare with the secret shown in the UI settings
```

If they do not match, re-deploy the action file with **Test connection** from the UI, or update the secret in the action file manually and restart Fail2Ban.

### Step 5: Simulate a ban notification with curl

This is the most direct way to test the full callback chain. Run it from any host that can reach the UI:

```bash
FAIL2BAN_UI_HOST="your_fail2ban_ui_host"
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

If it works, you should immediately see a new entry under "Recent stored events" on the dashboard, delivered as a real-time WebSocket update without refreshing.

Common error responses:

| Response | Cause |
|----------|-------|
| `401` with `"Callback secret not configured"` | No secret set in the UI settings |
| `401` with `"Invalid callback secret"` | Secret mismatch |
| `400` with `"invalid IP"` | The IP address in the payload is malformed |
| `400` with `"Invalid request"` | JSON parsing failed; check that `ip` and `jail` are present |

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

If the curl test works but real bans still do not show up, Fail2Ban itself might not execute the action correctly:

```bash
# Trigger a real ban (use a test jail or a test IP):
fail2ban-client set sshd banip 198.51.100.1

# Watch the Fail2Ban log for errors:
tail -f /var/log/fail2ban.log

# Look for lines like:
#   ERROR   ... Action ... failed
#   WARNING ... Command ... failed
```

You can also run the exact `curl` command from the action file manually. Extract it and substitute the Fail2Ban variables (`<ip>`, `<name>`, and so on) with real values:

```bash
grep -A5 "actionban" /etc/fail2ban/action.d/ui-custom-action.conf
```

Running it in a shell reveals whether `jq` is missing, `curl` has TLS issues, and similar problems. Common causes at this stage:

* **`jq` not installed.** The action file uses `jq` to build the JSON. Install it: `dnf install jq` or `apt install jq`.
* **TLS certificate issues.** A callback URL with HTTPS and a self-signed certificate needs the `-k` flag. Fail2Ban UI adds it automatically when the callback URL starts with `https://`.
* **Fail2Ban not restarted.** After the action file is deployed, Fail2Ban must be restarted to pick up the change: `systemctl restart fail2ban`.

### Step 7: Check the Fail2Ban UI logs

The UI logs every incoming callback:

```bash
# Container:
podman logs -f fail2ban-ui

# systemd:
journalctl -u fail2ban-ui -f

# Look for lines like:
#   Parsed ban request - IP: ..., Jail: ...
#   Invalid callback secret ...
#   JSON parsing error ...
```

With debug mode enabled in the UI settings, the raw JSON body of every incoming callback is logged as well.

### Step 8: Verify that the serverId resolves

The callback payload includes a `serverId`, which the UI uses to match the event to a configured server. If it matches no known server, the callback is rejected.

Check that the `serverId` in the action file matches the server ID shown under **Settings -> Manage Servers**:

```bash
curl -s http://$FAIL2BAN_UI_HOST:8080/api/servers \
  -H "X-F2B-Server: default" | jq '.servers[] | {id, name, hostname}'
```

### Quick reference: end-to-end callback flow

```
Fail2Ban detects an intrusion
  -> triggers actionban in ui-custom-action.conf
    -> curl POST /api/ban with JSON payload + X-Callback-Secret header
      -> Fail2Ban UI validates the secret
        -> validates the IP format
          -> resolves the server (by serverId)
            -> stores the event in SQLite (ban_events)
              -> broadcasts over WebSocket to all connected browsers
                -> optional: dispatches an alert (Email / Webhook / Elasticsearch)
                  -> optional: evaluates advanced actions (recurring offenders)
```

If any step fails, the chain stops and the event does not appear in the UI.

### Restored bans after a Fail2Ban service restart

The generated action file `/etc/fail2ban/action.d/ui-custom-action.conf` sets:

```ini
norestored = 1
```

With `norestored = 1`, Fail2Ban skips `actionban` and `actionunban` for ban events that are marked as *restored*. Why this is set, and what it means:

* After a Fail2Ban service restart, previously active blocks are loaded back from the persistence storage. Those bans are treated as restored, not as fresh bans in the current process. This is intended behavior - re-running the actions would flood the UI and any connected log-management system with duplicate events.
* As a consequence, if you unban one of those restored IPs, Fail2Ban does *not* execute `actionunban`. Fail2Ban UI never receives the `POST /api/unban`, so no unban toast and no new row under "Recent stored events" appears.
* Bans created *after* the last restart, and unbanned *without* another restart in between, go through the normal action pipeline. For those, ban and unban callbacks behave as expected.

The symptom "unban works, but the UI only records unbans for *new* blocks" therefore matches `norestored = 1` combined with a Fail2Ban restart between the original ban and the unban.

## Alert provider issues

### Alerts not sent (any provider)

1. Verify that alerts are enabled for the event type (ban and/or unban) under **Settings -> Alert Settings**.
2. Check which alert provider is selected, and re-check all settings of the active provider.
3. Check the country filter: if specific countries are selected, only IPs geolocated to those countries trigger alerts. Set it to `ALL` to alert on every event.
4. Confirm the dispatch in the Fail2Ban UI logs (enable debug logging for more detail):

```bash
podman logs -f fail2ban-ui

# Successful email alert:
#   sendEmail: Successfully sent email to ...
# Successful webhook:
#   Webhook alert sent successfully
# Successful Elasticsearch:
#   Elasticsearch alert indexed successfully
```

### Email: test email works, but ban alerts do not arrive

This typically happens because a real ban alert looks different from a test email - it contains IPs, special characters, and possibly attack payloads, which can trigger spam filtering. Check:

* The Fail2Ban UI logs show "Successfully sent email" for the ban event. If so, the problem is not on the Fail2Ban UI side.
* The email may be landing in spam. Check the spam or junk folder.
* Some SMTP servers, especially Office365, are strict about message formatting. Fail2Ban UI uses `\r\n` line endings and includes `Message-ID` and `Date` headers for compliance, but strict policies may still require a whitelist entry in the company's spam policy. Make sure you run the latest version.

### Webhook: HTTP 400 or connection errors

Common causes:

* **ntfy returns 400 "topic invalid".** ntfy requires the topic in the URL path, for example `https://ntfy.sh/fail2ban-alerts`, not just the base URL. With JSON payloads, the topic must be either in the URL path or in the JSON body as a `topic` field.
* **Connection refused.** The webhook URL is not reachable from the Fail2Ban UI host. Test with curl from the same host or container.
* **401/403.** The endpoint requires authentication. Add the appropriate header in the Custom Headers field, for example `Authorization: Bearer <token>`.
* **TLS certificate errors.** For self-signed endpoints, enable **Skip TLS Verification**.

Manual test:

```bash
curl -v -X POST https://your-webhook-url \
  -H "Content-Type: application/json" \
  -d '{"event":"test","ip":"203.0.113.1","jail":"sshd","hostname":"testhost","country":"US","failures":"3","timestamp":"2026-02-23T00:00:00Z"}'
```

### Elasticsearch: connection or indexing failures

Common causes:

* **Connection refused / timeout.** Verify that the Elasticsearch URL is reachable from the Fail2Ban UI host.
* **401 Unauthorized.** API key or credentials are incorrect. Verify the key in Kibana under **Stack Management -> API Keys**.
* **403 Forbidden.** The API key lacks write permissions on the target index. Create a key with `write` and `create_index` privileges for `fail2ban-events-*`.
* **Index template missing.** Without a template, Elasticsearch uses dynamic mapping, which may produce suboptimal field types. Create the template as described in [alert-providers.md](alert-providers.md#elasticsearch-setup).

Manual test:

```bash
curl -v -X POST "https://your-es-url/fail2ban-events-test/_doc" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey YOUR_BASE64_KEY" \
  -d '{"@timestamp":"2026-02-23T00:00:00Z","event.kind":"alert","event.type":"test","source.ip":"203.0.113.1"}'
```

### Switching providers

When switching alert providers, for example from Email to Webhook:

1. The previous provider's settings are preserved in the database; switching back restores them.
2. Save the settings after changing the provider.
3. Always use the test button for the new provider before relying on it for real events.

## Bans fail due to the firewall backend (nftables / firewalld)

Symptoms often mention `iptables (nf_tables)` or action startup errors. Use a banaction that matches the host's firewall backend:

| Backend | Banaction | Banaction allports |
|---------|-----------|--------------------|
| firewalld (RHEL, Rocky Linux, AlmaLinux) | `firewallcmd-rich-rules` | `firewallcmd-allports` |
| nftables | `nftables-multiport` | `nftables-allports` |
| legacy iptables | `iptables-multiport` | `iptables-allports` |

## OIDC login problems

Check:

* The issuer URL is correct and reachable.
* The redirect URI matches exactly: `https://<host>/auth/callback` (including any `BASE_PATH`).
* The provider client configuration includes the post-logout redirect `https://<host>/auth/login`.

```bash
podman logs fail2ban-ui
# Enable debug logging through the environment or the web UI for more detail.
```

## WebSocket not connecting

If real-time dashboard updates - ban and unban events appearing without a page refresh - do not work, check:

* The browser console for WebSocket errors (F12 -> Console).
* The WebSocket status indicator in the UI footer.
* The reverse proxy, if one is used, supports WebSocket upgrades.

Common causes:

* **Reverse proxy not forwarding WebSocket.** Nginx requires an explicit upgrade configuration:

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

* **Origin mismatch.** The WebSocket endpoint validates that the `Origin` header matches the `Host` header. If the reverse proxy rewrites `Host` but not `Origin`, the connection is rejected. Keep both headers consistent.
* **OIDC session expired.** With OIDC enabled, the WebSocket requires a valid session. After expiry, the connection fails with a 302 redirect or a 401 error. Log in to the UI again.

## Database issues

Check:

* `/config` is writable by the container or service user.
* The SQLite file permissions are correct.

```bash
ls -la /opt/fail2ban-ui
sqlite3 /opt/fail2ban-ui/fail2ban-ui.db "PRAGMA integrity_check;"
```

Expected output: `ok`. Any other output indicates a problem - investigate filesystem errors and restore from backup if needed.

## Reverse proxy checks

If the UI loads but real-time updates fail:

* Verify the proxy forwards WebSocket upgrades to `/api/ws`.
* Ensure the proxy preserves `Host` and does not create an `Origin`/`Host` mismatch.
* Confirm TLS termination and the backend route target are correct.

Reference configurations: [reverse-proxy.md](reverse-proxy.md).
