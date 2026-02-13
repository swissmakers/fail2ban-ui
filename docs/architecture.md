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