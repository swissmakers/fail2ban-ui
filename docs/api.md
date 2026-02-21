# API reference

This is a short index for operators. The UI primarily uses these endpoints. Paths and details may evolve; treat this as a practical reference.

## Authentication

- When OIDC is enabled, all `/api/*` endpoints (including WebSocket) require an authenticated session, except the callback endpoints.
- Callback endpoints (`/api/ban`, `/api/unban`) are authenticated using `X-Callback-Secret`.

## Input validation

All endpoints that accept IP addresses validate them server-side using Go's `net.ParseIP` / `net.ParseCIDR`. Requests with invalid IPs receive a `400 Bad Request` response. This applies to ban/unban callbacks, manual ban/unban from the dashboard, and the advanced actions test endpoint.

## Common headers

- `X-F2B-Server: <server-id>`  
  Used by the UI to select the target server in multi-server setups (where applicable).

## Endpoints

### Server management
- `GET /api/servers` -> List configured servers
- `POST /api/servers` -> Create or update a server
- `DELETE /api/servers/:id` -> Delete a server
- `POST /api/servers/:id/default` -> Set server as default
- `POST /api/servers/:id/test` -> Test server connectivity
- `GET /api/ssh/keys` -> List available SSH keys

### Jails and configuration
- `GET /api/summary` -> Dashboard summary (jails, banned IPs per server)
- `GET /api/jails/manage` -> List jails with enabled/disabled status
- `POST /api/jails/manage` -> Update jail enabled/disabled state
- `POST /api/jails` -> Create a new jail
- `DELETE /api/jails/:jail` -> Delete a jail
- `GET /api/jails/:jail/config` -> Get jail/filter configuration
- `POST /api/jails/:jail/config` -> Update jail/filter configuration
- `POST /api/jails/:jail/logpath/test` -> Test log path accessibility
- `POST /api/jails/:jail/unban/:ip` -> Unban an IP from a jail
- `POST /api/jails/:jail/ban/:ip` -> Ban an IP in a jail

### Events and analytics
- `GET /api/events/bans` -> List ban/unban events (paginated, filterable)
- `DELETE /api/events/bans` -> Delete all stored ban events
- `GET /api/events/bans/stats` -> Ban statistics (counts, timeseries)
- `GET /api/events/bans/insights` -> Ban insights (countries, top IPs, top jails)

### Advanced actions
- `GET /api/advanced-actions/blocks` -> List permanent block records
- `DELETE /api/advanced-actions/blocks` -> Delete all permanent block records
- `POST /api/advanced-actions/test` -> Manually test block/unblock on configured integration

### Settings
- `GET /api/settings` -> Get current application settings
- `POST /api/settings` -> Update application settings
- `POST /api/settings/test-email` -> Send a test email

### Filter management
- `GET /api/filters` -> List available filters
- `GET /api/filters/:filter/content` -> Get filter file content
- `POST /api/filters` -> Create a new filter
- `POST /api/filters/test` -> Test filter regex against log lines
- `DELETE /api/filters/:filter` -> Delete a filter

### Service control
- `POST /api/fail2ban/restart` -> Restart / Reloads the Fail2Ban service

### Version
- `GET /api/version` -> Get running version and optional update check

### WebSocket
- `GET /api/ws` -> WebSocket endpoint (upgrade)

The WebSocket connection streams, real-time events to the frontend:
- `heartbeat` -> periodic health check (~30s)
- `console_log` -> debug console log lines (when debug mode is enabled)
- `ban_event` -> real-time ban event broadcast
- `unban_event` -> real-time unban event broadcast

The WebSocket enforces same-origin policy via the `Origin` header and requires authentication when OIDC is enabled.

### Callbacks (Fail2Ban actions)
- `POST /api/ban` -> Receive ban notification from Fail2Ban
- `POST /api/unban` -> Receive unban notification from Fail2Ban

Callbacks require:
- Header: `X-Callback-Secret: <secret>`
- JSON body fields (typical): `serverId`, `ip`, `jail`, `hostname`, `failures`, `logs`

All IPs in callback payloads are validated before processing.

### Authentication routes (OIDC)
- `GET /auth/login` -> Initiate OIDC login flow
- `GET /auth/callback` -> OIDC provider callback
- `GET /auth/logout` -> Logout and clear session
- `GET /auth/status` -> Check authentication status
- `GET /auth/user` -> Get current user info