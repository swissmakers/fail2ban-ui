# Architecture overview

Fail2Ban UI consists of :
- a Go HTTP API (Gin)
- a single-template web frontend (with static assets)
- an embedded SQLite database for state and event history
- optional integrations (Email, GeoIP/Whois, firewalls)

## Data flows

1) User -> UI -> API
- Browser communicates with the backend via HTTP and WebSocket.
- When OIDC is enabled, most UI routes require authentication.

2) Fail2Ban host -> UI callbacks
- A custom Fail2Ban action posts ban/unban events to the UI.
- The UI validates the callback secret, enriches (optional), stores, and broadcasts events.

3) UI -> Fail2Ban host (management operations)
- Local: uses the Fail2Ban socket and local filesystem.
- SSH: runs `fail2ban-client` and manages files via SSH.
- Agent (preview): HTTP-based control plane (limited, in progress).

## Components (high level)

- REST API: server management, jail/filter config read/write, ban/unban actions, settings
- WebSocket hub: streams ban/unban events and (optional) debug console logs
- Storage: server definitions, settings, ban history, permanent block records

Additional resources:
- Container deployment guide: `deployment/container/README.md`
- systemd setup guide: `deployment/systemd/README.md`

## More detailed diagrams

#### Browser (Frontend) ↔ Backend (HTTP / WebSocket) communication

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│  FRONTEND (Vanilla JS + Tailwind CSS)                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │
│  │  Dashboard  │  │ Filter Debug│  │   Settings  │  │  (index)    │               │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘               │
│         └────────────────┴────────────────┴────────────────┘                      │
│                                    │                                              │
│  Communication to backend:         │  HTTP/HTTPS (REST)                           │
│  • GET  /                          │  • All /api/* (except callbacks) use your    │
│  • GET  /api/summary               │    session when OIDC is enabled              │
│  • GET  /api/events/bans           │  • X-F2B-Server header for server selection  │
│  • GET  /api/version               │                                              │
│  • POST /api/jails/:jail/unban/:ip │  WebSocket: GET /api/ws (upgrade)            │
│  • POST /api/jails/:jail/ban/:ip   │  • Same origin, same cookies as HTTP         │◀-┐
│  • POST /api/settings              │  • Receives: heartbeat, console_log,         │  │
│  • … (see diagram 2)               │    ban_event, unban_event                    │  │
└────────────────────────────────────┼──────────────────────────────────────────────┘  │ W
                                     │                                                 │ e
                                     ▼                                                 │ b
┌─────────────────────────────────────────────────────────────────────────────────┐    │ s
│  GO BACKEND (Gin)                                                               │    │ o
│  ┌───────────────────────────────────────────────────────────────────────────┐  │    │ c
│  │  PUBLIC (no OIDC-auth session needed for access):                         │  │    │ k
│  │  • /auth/login | /auth/callback | /auth/logout                            │  │    │ e
│  │  • /auth/status | /auth/user                                              │  │    │ t  
│  │  • POST /api/ban | POST /api/unban ← Fail2ban callbacks (a valid Callback │  │    │
│  │  • GET /api/ws   (WebSocket)                            Secret is needed) │  │    │
│  │  • /static/* | /locales/*                                                 │  │----┘
│  └───────────────────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  PROTECTED (when OIDC enabled):  GET / | GET and POST to all other /api/* │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### Backend internals: API routes, WebSocket hub, storage, connectors

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  GIN SERVER                                                                      │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │  REST API (group /api)                                                     │  │
│  │  • GET  /summary              → Connector(s) → Fail2ban(jails, banned IPs) │  │
│  │  • GET  /jails/:jail/config   • POST /jails/:jail/config                   │  │
│  │  • GET  /jails/manage         • POST /jails/manage | POST /jails           │  │
│  │  • POST /jails/:jail/unban/:ip  • POST /jails/:jail/ban/:ip                │  │
│  │  • GET  /settings             • POST /settings                             │  │
│  │  • GET  /events/bans          • GET /events/bans/stats | /insights         │  │
│  │  • GET  /version              (optional GitHub request if UPDATE_CHECK)    │  │
│  │  • GET  /servers | POST/DELETE /servers | POST /servers/:id/test           │  │
│  │  • GET  /filters/*            • POST /filters/test | POST/DELETE /filters  │  │
│  │  • POST /fail2ban/restart     • GET/POST /advanced-actions/*               │  │
│  │  • POST /ban  (callback)      • POST /unban (callback)                     │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                             │
│  ┌─────────────────────────────────┴──────────────────────────────────────────┐  │
│  │  WebSocket Hub (GET /api/ws)                                               │  │
│  │  • register / unregister clients                                           │  │
│  │  • broadcast to all clients:                                               │  │
│  │    - type: "heartbeat"   (every ~30s)                                      │  │
│  │    - type: "console_log" (debug console lines)                             │  │
│  │    - type: "ban_event"   (after POST /api/ban → store → broadcast)         │  │
│  │    - type: "unban_event" (after POST /api/unban → store → broadcast)       │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────┐  ┌────────────────────────────┐                  │
│  │  SQLite Storage            │  │  Whois / GeoIP             │                  │
│  │  • ban_events              │  │  • IP → country/hostname   │                  │
│  │  • app_settings, servers   │  │    MaxMind or ip-api.com   │                  │
│  │  • permanent_blocks        │  │  • Used in UI and emails   │                  │
│  └────────────────────────────┘  └────────────────────────────┘                  │
│  ┌────────────────────────────┐  ┌────────────────────────────┐                  │
│  │  Connector Manager         │  │  Integrations + Email      │                  │
│  │  • Local (fail2ban.sock)   │  │  • Mikrotik / pfSense /    │                  │
│  │  • SSH (exec on remote)    │  │    OPNsense (block/unblock)│                  │
│  │  • Agent (HTTP to agent)   │  │  • SMTP alert emails       │                  │
│  │  • New server init: ensure │  └────────────────────────────┘                  │
│  │    action.d (ui-custom-    │                                                  │
│  │    action.conf)            │                                                  │
│  └────────────────────────────┘                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

#### Fail2ban instances → Fail2ban-UI (callbacks) and Fail2ban-UI → Fail2ban (via connectors)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  FAIL2BAN INSTANCES (one per server: local, SSH host, or agent host)             │
│  On each host: Fail2ban + action script (ui-custom-action.conf)                  │
│  On ban/unban → action runs → HTTP POST to Fail2ban-UI callback URL              │
│                                                                                  │
│         ┌───────────────────────────────────────────────────────────────┐        │
│         │  Outbound to Fail2ban-UI (from each Fail2ban host)            │        │
│         │  POST <CallbackURL>/api/ban   or   /api/unban                 │        │
│         │  Header: X-Callback-Secret: <configured secret>               │        │
│         │  Body: JSON { serverId, ip, jail, hostname, failures, logs }  │        │
│         └───────────────────────────────────────────────────────────────┘        │
│                                    │                                             │
│                                    ▼                                             │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │  Fail2ban-UI Backend                                                       │  │
│  │  1. Validate X-Callback-Secret → 401 if missing/invalid                    │  │
│  │  2. Resolve server (serverId or hostname)                                  │  │
│  │  3. Whois/GeoIP enrichment                                                 │  │
│  │  4. Store event in SQLite DB (ban_events) if nothing was invalid           │  │
│  │  5. Broadcast current event to WebSocket clients (ban_event / unban_event) │  │
│  │  6. Optional: send SMTP alert                                              │  │
│  │  7  Run additional actions (e.g. block on pfSense for recurring offenders) │  │
│  │  8. Respond status 200 OK - if all above was without an error              │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│  INBOUND from Fail2ban-UI to Fail2ban (per connector type)                      │
│  • Local:  fail2ban-client over Unix socket (/var/run/fail2ban/fail2ban.sock)   │
│  • SSH:   SSH + fail2ban-client on remote host                                  │
│  • Agent: HTTP to agent API (e.g. /v1/jails/:jail/unban, /v1/jails/:jail/ban)   │
│  Used for: summary (jails, banned IPs), unban/ban from UI, config read/write,   │
│            filter test, jail create/delete, restart/reload, logpath test        │
└─────────────────────────────────────────────────────────────────────────────────┘
```