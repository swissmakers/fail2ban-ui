# API reference (summary)

This is a short index for operators. The UI primarily uses these endpoints. Paths and details may evolve; treat this as a practical reference.

## Authentication

- When OIDC is enabled, most `/api/*` endpoints require an authenticated session.
- Callback endpoints are authenticated using `X-Callback-Secret`.

## Common headers

- `X-F2B-Server: <server-id>`  
  Used by the UI to select the target server in multi-server setups (where applicable).

## Endpoints

Server management
- `GET /api/servers`
- `POST /api/servers`
- `DELETE /api/servers/:id`
- `POST /api/servers/:id/test`

Jails and configuration
- `GET /api/summary`
- `GET /api/jails/manage`
- `POST /api/jails/manage`
- `GET /api/jails/:jail/config`
- `POST /api/jails/:jail/config`
- `POST /api/jails/:jail/unban/:ip`
- `POST /api/jails/:jail/ban/:ip`

Events and analytics
- `GET /api/events/bans`
- `GET /api/events/bans/stats`
- `GET /api/events/bans/insights`

Settings
- `GET /api/settings`
- `POST /api/settings`
- `POST /api/settings/test-email`

Filter debugging
- `GET /api/filters`
- `POST /api/filters/test`

Service control
- `POST /api/fail2ban/restart`

Callbacks (Fail2Ban actions)
- `POST /api/ban`
- `POST /api/unban`

Callbacks require:
- Header: `X-Callback-Secret: <secret>`
- JSON body fields (typical): `serverId`, `ip`, `jail`, `hostname`, `failures`, `logs`

Authentication routes (OIDC)
- `GET /auth/login`
- `GET /auth/callback`
- `GET /auth/logout`
- `GET /auth/status`
- `GET /auth/user`