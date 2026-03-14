# Webhook Integration Guide

This guide covers webhook behavior in Fail2Ban UI and provides practical integration patterns.

## Webhook integration model

Fail2Ban UI sends a generic JSON payload. Some platforms accept it directly; others require a transformer/relay.

Example payload:

```json
{
  "event": "ban",
  "ip": "203.0.113.42",
  "jail": "sshd",
  "hostname": "edge-01",
  "country": "DE",
  "failures": "5",
  "whois": "...",
  "logs": "...",
  "timestamp": "2026-03-14T11:45:00Z"
}
```

## Direct webhook examples

### ntfy

- Webhook URL: `https://ntfy.example.com/fail2ban-alerts`
- Method: `POST`
- Optional headers:
  - `Title: Fail2Ban Alert`
  - `Priority: high`
  - `Tags: rotating_light`
  - `Authorization: Bearer <token>` (if protected)

### Generic internal endpoint

- Webhook URL: `https://alerts.internal.example/api/fail2ban`
- Method: `POST`
- Header example: `Authorization: Bearer <service-token>`


## Relay integration (example for e.g. Telegram)

If a API does not natively consume the generic Fail2Ban UI payload format as-is; for example the Telegram Bot, you need to use a relay/automation layer (for example n8n, Node-RED, Make, or a small custom service).

### Example Option 1 -> n8n flow (recommended)

1. In Fail2Ban UI, set webhook URL to your n8n webhook endpoint.
2. In n8n:
   - Trigger: Webhook node (receives Fail2Ban payload)
   - Transform: Set/Function node to build message text
   - Action: Telegram node (`sendMessage`) using bot token and chat ID

Example message template:

```text
[Fail2Ban] {{$json.event | upperCase}}
IP: {{$json.ip}}
Jail: {{$json.jail}}
Host: {{$json.hostname}}
Country: {{$json.country}}
Time: {{$json.timestamp}}
```

### Example Option 2 -> minimal relay service

Build a small HTTP service that:

1. Accepts Fail2Ban UI payload.
2. Formats a concise text message.
3. Calls `https://api.telegram.org/bot<TOKEN>/sendMessage` with `chat_id` and `text`.

This approach is also suitable for Slack, Mattermost, Teams, and Discord transformations.