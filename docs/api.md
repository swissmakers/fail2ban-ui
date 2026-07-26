# API reference

This is a practical endpoint index for operators. The web frontend uses these endpoints; paths and details may evolve between releases.

## Authentication

* When OIDC is enabled, all `/api/*` endpoints, including the WebSocket, require an authenticated session - except the machine-to-machine endpoints listed below.
* Optional OIDC role-based access control can further restrict authenticated users. `admin` users can access everything; `support` users can view operational dashboard/event data and manually ban/unban IPs.
* The machine-to-machine endpoints (`POST /api/ban`, `POST /api/unban`, `GET /api/healthcheck/callback`) are exempt from the session check and are authenticated through the `X-Callback-Secret` header instead.

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
| `GET /api/ips/:ip/search` | Search every configured server for jails that currently ban this IP |

`GET /api/ips/:ip/search` queries all connectors in parallel against the *live* Fail2Ban state, not the stored event history, with a 15-second timeout per server. Response:

```json
{
  "ip": "203.0.113.10",
  "banned": true,
  "matches": [{ "serverId": "...", "serverName": "...", "jail": "sshd" }],
  "errors":  [{ "serverId": "...", "serverName": "...", "error": "..." }]
}
```

A server that is unreachable is reported in `errors` and does not fail the request.

`POST /api/jails/:jail/logpath/test` accepts an optional body `{"logpath": "..."}`; when omitted, the log path stored in the jail configuration is used. Paths separated by spaces or newlines are tested individually and each returns one result object:

| Field | Meaning |
|-------|---------|
| `logpath` | The path as configured |
| `resolved_path` | The path after variable and wildcard resolution |
| `found` | `true` when at least one matching file exists |
| `files` | The matched files |
| `error` | Non-empty when the test genuinely failed |
| `inaccessible` | `true` when the log directory could not be read by the connector's SSH user |
| `message` | Human-readable explanation, currently set for the `inaccessible` case |

`inaccessible: true` is a warning, not a failure: Fail2Ban runs as root on the managed host and will read the path regardless, so the jail can still be enabled. The UI renders this state in yellow, distinct from the red not-found and error states.

### Events and analytics

| Method and path | Description |
|-----------------|-------------|
| `GET /api/events/bans` | List ban and unban events, paginated and filterable |
| `GET /api/events/bans/:id` | Read a single ban event, including the stored whois text and log lines |
| `DELETE /api/events/bans` | Delete all stored ban events |
| `GET /api/events/bans/countries` | Distinct country codes present in the stored events; populates the country filter |
| `GET /api/events/bans/stats` | Ban statistics: counts and time series |
| `GET /api/events/bans/insights` | Ban insights: country distribution and recurring IPs (`minCount`, `limit` query parameters) |
| `GET /api/events/bans/timeline` | Time-bucketed ban/unban counts for the insights timeline |
| `GET /api/events/bans/ips` | Per-IP ban aggregates for a time range |
| `GET /api/events/bans/ips/activity` | Per-IP activity periods, for the insights activity view |

**Range and filter parameters.** `timeline`, `ips`, and `ips/activity` accept `since` and `until` as RFC3339 timestamps. The default range is the last 8 hours (`until` = now, `since` = 8 hours earlier). All three also accept the filters `serverId`, `jail`, `country`, and `search`. An unparseable timestamp, or `until` not after `since`, returns `400`.

* `timeline` accepts an optional `bucket` in seconds. The server chooses the bucket size automatically and raises any override that would produce too many buckets. Response: `{ since, until, bucketSeconds, buckets, totals: { bans, unbans } }`.
* `ips` accepts `limit` (default `2000`, maximum `10000`) and returns `{ ips, total, truncated, since, until }`.
* `ips/activity` accepts `minOverlap` (default `3`) and returns `{ periods }`.

**Paging and search on `GET /api/events/bans`.** Text search uses an SQLite FTS5 index and falls back to `LIKE` matching if the index is unavailable. Result counts are capped server-side at 5000: a `total` of `5001` means "more than 5000 matches", not an exact count.

Stored events are pruned on a schedule; see [configuration.md](configuration.md#event-retention-ui-managed).

### Advanced actions

| Method and path | Description |
|-----------------|-------------|
| `GET /api/advanced-actions/blocks` | List permanent block records |
| `POST /api/advanced-actions/blocks` | Bulk permanent block for a list of IPs, used by the ban-insights modal |
| `DELETE /api/advanced-actions/blocks` | Delete all permanent block records |
| `POST /api/advanced-actions/test` | Manually test block/unblock on the configured integration |

`POST /api/advanced-actions/blocks` takes `{"ips": ["203.0.113.10", "..."]}`, at most 500 addresses per request. It requires a configured and valid advanced-actions integration (MikroTik, pfSense, or OPNsense); otherwise it returns `400`. Duplicates are removed while preserving order, and loopback, link-local, multicast, unspecified, and private addresses are skipped. After five consecutive identical integration errors the run aborts and the remaining addresses are returned with status `aborted`.

Response: `{ "results": [{ "ip", "status", "message" }], "summary": { "requested", "blocked", "alreadyBlocked", "skipped", "invalid", "failed", "aborted" } }`, where `status` is one of `blocked`, `already_blocked`, `skipped_private`, `invalid`, `error`, or `aborted`. `summary.requested` counts the addresses left after deduplication.

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

### Health check

| Method and path | Description |
|-----------------|-------------|
| `GET /api/healthcheck/callback` | Validates the `X-Callback-Secret` header without side effects and returns `{"ok": true}` |

This endpoint lets a managed host - primarily the [fail2ban-ui-agent](https://github.com/swissmakers/fail2ban-ui-agent) - confirm that it holds the correct callback secret before it starts posting events. Like `/api/ban` and `/api/unban`, it is exempt from the OIDC session check and is protected only by the callback secret. A missing, unconfigured, or mismatched secret returns `401`.

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
| `ban_event_update` | Enrichment update for an event that was already delivered, sent once the asynchronous Whois/GeoIP lookup completes |

All message types are carried on the single `/api/ws` connection; there is no second WebSocket endpoint. `ban_event_update` is emitted after the callback response has already been returned: the event is stored and broadcast immediately, while the Whois and GeoIP lookups, which can take several seconds, run in the background. When they finish, the enriched record is broadcast, with the `whois` and `logs` fields stripped from the payload, so the frontend can merge the resolved country into the row it is already displaying.

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
