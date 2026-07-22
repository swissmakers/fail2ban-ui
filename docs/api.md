# API reference

This is a practical endpoint index for operators. The web frontend uses these endpoints; paths and details may evolve between releases.

## Authentication

* When OIDC is enabled, all `/api/*` endpoints, including the WebSocket, require an authenticated session - except the callback endpoints.
* Optional OIDC role-based access control can further restrict authenticated users. `admin` users can access everything; `support` users can view operational dashboard/event data and manually ban/unban IPs.
* The callback endpoints (`/api/ban`, `/api/unban`) are authenticated through the `X-Callback-Secret` header.

## Input validation

Every endpoint that accepts an IP address validates it server-side with Go's `net.ParseIP` / `net.ParseCIDR`. Requests with invalid IPs receive `400 Bad Request`. This applies to the ban/unban callbacks, manual ban/unban from the dashboard, and the advanced-actions test endpoint.

## Common headers

| Header | Purpose |
|--------|---------|
| `X-F2B-Server: <server-id>` | Selects the target server in multi-server setups, where applicable |

## Endpoints

### Server management

| Method and path | Description |
|-----------------|-------------|
| `GET /api/servers` | List configured servers |
| `POST /api/servers` | Create or update a server |
| `DELETE /api/servers/:id` | Delete a server |
| `POST /api/servers/:id/default` | Set a server as the default |
| `POST /api/servers/:id/test` | Test server connectivity |
| `GET /api/ssh/keys` | List available SSH keys |

### Jails and configuration

| Method and path | Description |
|-----------------|-------------|
| `GET /api/summary` | Dashboard summary: jails and counters; banned IP lists are loaded separately |
| `GET /api/jails/:jail/banned` | Paginated banned-IP list for one jail (`limit`, `offset`, optional `q` search) |
| `GET /api/jails/manage` | List jails with their enabled/disabled state |
| `POST /api/jails/manage` | Update the enabled/disabled state of a jail |
| `POST /api/jails` | Create a jail |
| `DELETE /api/jails/:jail` | Delete a jail |
| `GET /api/jails/:jail/config` | Read jail and filter configuration |
| `POST /api/jails/:jail/config` | Update jail and filter configuration |
| `POST /api/jails/:jail/logpath/test` | Test log path accessibility |
| `POST /api/jails/:jail/ban/:ip` | Ban an IP in a jail |
| `POST /api/jails/:jail/unban/:ip` | Unban an IP from a jail |

### Events and analytics

| Method and path | Description |
|-----------------|-------------|
| `GET /api/events/bans` | List ban and unban events, paginated and filterable |
| `DELETE /api/events/bans` | Delete all stored ban events |
| `GET /api/events/bans/stats` | Ban statistics: counts and time series |
| `GET /api/events/bans/insights` | Ban insights: countries, top IPs, top jails |

### Advanced actions

| Method and path | Description |
|-----------------|-------------|
| `GET /api/advanced-actions/blocks` | List permanent block records |
| `DELETE /api/advanced-actions/blocks` | Delete all permanent block records |
| `POST /api/advanced-actions/test` | Manually test block/unblock on the configured integration |

### Settings

| Method and path | Description |
|-----------------|-------------|
| `GET /api/settings` | Read the current application settings |
| `POST /api/settings` | Update application settings |
| `POST /api/settings/test-email` | Send a test email (Email provider) |
| `POST /api/settings/test-webhook` | Send a test webhook payload (Webhook provider) |
| `POST /api/settings/test-elasticsearch` | Index a test document (Elasticsearch provider) |

The settings payload includes the alert provider configuration (`alertProvider`, `webhook`, and `elasticsearch` fields). See [alert-providers.md](alert-providers.md) for the full provider documentation.

### Filter management

| Method and path | Description |
|-----------------|-------------|
| `GET /api/filters` | List available filters |
| `GET /api/filters/:filter/content` | Read filter file content |
| `POST /api/filters` | Create a filter |
| `POST /api/filters/test` | Test a filter regex against log lines |
| `DELETE /api/filters/:filter` | Delete a filter |

### Service control

| Method and path | Description |
|-----------------|-------------|
| `POST /api/fail2ban/restart` | Restart or reload the Fail2Ban service |

### Threat intelligence

| Method and path | Description |
|-----------------|-------------|
| `GET /api/threat-intel/:ip` | Query the configured threat-intel provider (AlienVault OTX or AbuseIPDB) for an IP |

Behavior:

* Validates `:ip` server-side.
* Requires a threat-intel provider to be enabled in settings (`alienvault` or `abuseipdb`); returns `409` when the provider is `none`.
* Uses a provider+IP cache (30 minutes) and retry/backoff handling for upstream `429` responses.
* May include an `X-Threat-Intel-Cache: hit|stale` response header.

See [threat-intel.md](threat-intel.md) for setup and full behavior.

### Version

| Method and path | Description |
|-----------------|-------------|
| `GET /api/version` | Running version, with an optional update check (GitHub request when `UPDATE_CHECK` is enabled) |

### WebSocket

| Method and path | Description |
|-----------------|-------------|
| `GET /api/ws` | WebSocket upgrade endpoint |

The connection streams real-time events to the frontend:

| Message type | Description |
|--------------|-------------|
| `heartbeat` | Periodic health check, about every 30 seconds |
| `console_log` | Debug console log lines, when debug mode is enabled |
| `ban_event` | Real-time ban event broadcast |
| `unban_event` | Real-time unban event broadcast |

The WebSocket enforces a same-origin policy through the `Origin` header and requires authentication when OIDC is enabled.

### Callbacks (Fail2Ban actions)

| Method and path | Description |
|-----------------|-------------|
| `POST /api/ban` | Receive a ban notification from Fail2Ban |
| `POST /api/unban` | Receive an unban notification from Fail2Ban |

Callbacks require:

* Header: `X-Callback-Secret: <secret>`
* JSON body fields (typical): `serverId`, `ip`, `jail`, `hostname`, `failures`, `logs`

All IPs in callback payloads are validated before processing. After validation, the callback triggers:

1. Event storage in the database
2. WebSocket broadcast to connected clients
3. Alert dispatch to the configured provider (Email, Webhook, or Elasticsearch), if alerts are enabled and the country filter matches

### Authentication routes (OIDC)

| Method and path | Description |
|-----------------|-------------|
| `GET /auth/login` | Initiate the OIDC login flow |
| `GET /auth/callback` | OIDC provider callback |
| `GET /auth/logout` | Log out and clear the session |
| `GET /auth/status` | Check authentication status |
| `GET /auth/user` | Read current user information |
