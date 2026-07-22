# Architecture

Fail2Ban UI is a single Go binary that provides centralized management for one or more Fail2Ban instances. It does not replace Fail2Ban: every ban decision is still made by the Fail2Ban daemon on the individual host. The UI adds a management layer on top of it.

The application consists of the following parts:

- An HTTP API and embedded web frontend, served by a Gin HTTP server
- A WebSocket hub for real-time event delivery to the browser
- An embedded SQLite database for server definitions, settings, ban history, and permanent block records
- A connector manager that talks to the managed Fail2Ban instances
- Optional integrations: alert providers, GeoIP/Whois enrichment, and edge firewall actions

Fail2Ban UI system architecture
[![Architecture-Diagram](diagrams/architecture.drawio.svg)](diagrams/architecture.drawio.svg)

## Design principles

- **Two independent paths.** Management commands flow from the UI to Fail2Ban (control path). Ban and unban events flow from Fail2Ban to the UI (event path). The two directions use different transports and different authentication (also varies per connector).
- **No required inbound ports on managed hosts beyond what already exists.** The SSH connector reuses `sshd`. The agent connector exposes a single HTTP endpoint. The local connector uses the Fail2Ban Unix socket.
- **Validate at the boundary.** Every IP address and CIDR received from the API or a callback is parsed with `net.ParseIP` / `net.ParseCIDR` before it reaches a shell command, an SSH session, or a firewall integration. Identifiers passed to integrations are sanitized.
- **State lives in one place.** All persistent state is kept in the embedded SQLite database under the configuration directory. A backup of that directory is a complete backup of the UI.

## Connectors

A *connector* is the mechanism the UI uses to control a single Fail2Ban instance. Each managed server is configured with exactly one connector type. The connector is selected per request through the `X-F2B-Server` HTTP header.


| Connector | Transport                                                                             | Typical use                                                                   | Requirements on the managed host                                                                                   |
| --------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Local     | Unix socket and direct file access                                                    | Fail2Ban runs on the same host as the UI                                      | Read/write access to `/var/run/fail2ban/fail2ban.sock` and `/etc/fail2ban`; read access to the monitored log files |
| SSH       | SSH with key-based authentication                                                     | Remote hosts where installing additional software is not wanted               | A dedicated service account with `sudo fail2ban-client `* and `sudo systemctl restart fail2ban`                    |
| Agent     | HTTP to the [fail2ban-ui-agent](https://github.com/swissmakers/fail2ban-ui-agent) API | Environments where SSH access from the UI host is not desired or not possible | The agent service, with local access to the Fail2Ban socket and configuration                                      |


All three connectors implement the same operations: reading the jail summary and banned IPs, banning and unbanning addresses, reading and writing jail and filter configuration, testing filters and log paths, creating and deleting jails, and restarting or reloading Fail2Ban.

When a new server is added, the connector also installs the callback action (`ui-custom-action.conf`) into `action.d` on the managed host, so that the Event path works without manual configuration.

## Data flows

### Control path -- Fail2Ban-UI to Fail2Ban

Management operations originate from the REST API and are executed by the connector assigned to the target server:

- **Local** invokes `fail2ban-client` against the Unix socket and edits configuration files directly on the filesystem.
- **SSH** opens a session as the configured service account and runs `sudo fail2ban-client`; configuration files are transferred over the same SSH connection.
- **Agent** issues HTTP requests to the agent API (for example `POST /v1/jails/:jail/ban`); the agent performs the socket and file operations locally. The agent URL accepts either a bare host (defaults to `http://<host>:9700`, the agent's native port) or a full `http(s)://` URL, which is used exactly as entered - so an agent behind a reverse proxy on a standard port works with, for example, `https://fail2ban-agent.example.com/`.

### Event path -- Fail2Ban to Fail2Ban-UI

Each managed Fail2Ban instance carries a custom action, `ui-custom-action.conf`, attached to its jails. On every ban and unban, the action sends an HTTP `POST` to the UI callback endpoint:

```
POST <callback-url>/api/ban     (or /api/unban)
X-Callback-Secret: <configured secret>
Content-Type: application/json

{ "serverId": "...", "ip": "...", "jail": "...", "hostname": "...", "failures": ..., "logs": [...] }
```

The backend processes each callback in the following order:

1. Validate the `X-Callback-Secret` header. Requests with a missing or invalid secret are rejected with `401` and are not processed further.
2. Resolve the originating server from `serverId` or, as a fallback, the reported hostname.
3. Validate the IP address and enrich the event with GeoIP and Whois data, if enrichment is enabled.
4. Store the event in the `ban_events` table.
5. Broadcast the event (`ban_event` or `unban_event`) to all connected WebSocket clients.
6. Dispatch alerts to the configured providers, subject to the per-event and country filters.
7. Evaluate advanced ban actions. If a recurring-offender threshold is reached, the address is pushed as a permanent block to the configured edge firewall (MikroTik, pfSense, or OPNsense) and recorded in `permanent_blocks`.
8. Return `200 OK`.

**Note:** The callback endpoints (`/api/ban`, `/api/unban`) are intentionally reachable without an OIDC session, because they are called by machines, not by users. They are protected exclusively by the callback secret. Treat the secret like a credential and only transport callbacks over TLS or a trusted network.

### Browser to Fail2Ban-UI

The browser communicates with the backend over HTTPS (REST) and a WebSocket connection (`GET /api/ws`):

- When OIDC is enabled, the index page, all `/api/`* routes except the callbacks, and the WebSocket upgrade require an authenticated session. The login flow (`/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/status`, `/auth/user`) and static assets remain public.
- The WebSocket hub validates the `Origin` header against the request `Host` and rejects cross-site connections. Connected clients receive `heartbeat` (about every 30 seconds), `console_log` (debug console), `ban_event`, and `unban_event` messages.

## Backend components


| Component             | Responsibility                                                                                                                                                                    |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| REST API (`/api`)     | Server management, jail and filter configuration, ban/unban actions, settings, event queries and insights, data management (clearing events and blocks), version and update check |
| WebSocket hub         | Client registration, origin validation, broadcast of heartbeat, console, and ban/unban messages                                                                                   |
| SQLite storage        | `ban_events`, `app_settings`, `servers`, `permanent_blocks`                                                                                                                       |
| Connector manager     | One connector instance per configured server; installs the callback action on new servers                                                                                         |
| Alert dispatcher      | Pluggable providers: Email (SMTP), Webhook, Elasticsearch; per-event toggles and country-based filtering                                                                          |
| GeoIP / Whois         | IP-to-country and hostname resolution through MaxMind databases or ip-api.com; used in the UI, in alerts, and in ban insights                                                     |
| Firewall integrations | MikroTik over SSH, pfSense and OPNsense over their REST APIs; all parameters validated before dispatch                                                                            |


## Network requirements


| Path                      | Protocol / port                                                  | Direction        | Authentication                     |
| ------------------------- | ---------------------------------------------------------------- | ---------------- | ---------------------------------- |
| Browser -> Fail2ban-UI             | HTTPS / WSS, port 8080 by default (place behind a reverse proxy) | inbound to Fail2ban-UI    | OIDC session (optional)            |
| Fail2ban-UI -> SSH-connected host   | SSH, port 22                                                     | outbound from Fail2ban-UI | SSH key, dedicated service account |
| Fail2ban-UI -> agent-connected host | HTTP(S), agent port                                              | outbound from Fail2ban-UI | Agent token                        |
| Fail2Ban host -> Fail2ban-UI        | HTTP(S) `POST /api/ban`, `/api/unban`                            | inbound to Fail2ban-UI    | `X-Callback-Secret` header         |
| Fail2ban-UI -> alert providers      | SMTP / HTTPS / Elasticsearch API                                 | outbound from Fail2ban-UI | Provider-specific                  |
| Fail2ban-UI -> edge firewall        | SSH (MikroTik) or HTTPS (pfSense, OPNsense)                      | outbound from Fail2ban-UI | Device credentials / API token     |


**Important:** Do not expose the Fail2ban-UI directly to the public Internet. Place it behind a reverse proxy, VPN, or firewall rules, and enable OIDC where possible. The callback endpoint is the only path that managed hosts must be able to reach.

## Additional resources

- [Installation](installation.md)
- [Configuration reference](configuration.md) - environment variables, callback URL and secret, OIDC
- [Reverse proxy guide](reverse-proxy.md) - production proxy examples and WebSocket requirements
- [Security guidance](security.md) - deployment posture, SELinux notes
- [Alert providers](alert-providers.md)
- [Threat intelligence](threat-intel.md)
- [API reference](api.md)
- Deployment guides: [container](../deployment/container/README.md), [systemd](../deployment/systemd/README.md)
- Remote agent: [fail2ban-ui-agent](https://github.com/swissmakers/fail2ban-ui-agent)