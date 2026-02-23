# Alert providers

Fail2Ban UI can send alert notifications when a ban or unban event occurs. Three providers are available: **Email (SMTP)**, **Webhook**, and **Elasticsearch**. Only one provider can be active at a time.

All providers share the same global settings:

- **Enable alerts for bans / unbans** -> master toggles that control whether any alert fires.
- **Alert Countries** -> only events for IPs geolocated to the selected countries trigger alerts. Set to `ALL` to alert on every country.
- **GeoIP Provider** -> determines how country lookups are performed (built-in API or local MaxMind database).
- **Maximum Log Lines** -> limits the number of log lines attached to alert payloads.

## Email (SMTP)

The default provider. Sends HTML-formatted emails via a configured SMTP server.

### Settings

| Field | Description |
|---|---|
| Destination Email | The recipient address for all alert emails |
| SMTP Host | Mail server hostname (e.g. `smtp.office365.com`) |
| SMTP Port | Common values: 587 (STARTTLS), 465 (implicit TLS), 25 (plain) |
| SMTP Username | Login username for the mail server |
| SMTP Password | Login password or app password |
| Sender Email | The `From:` address on outgoing alerts |
| Authentication Method | `Auto` (LOGIN preferred), `LOGIN`, `PLAIN`, or `CRAM-MD5` |
| Use TLS | Enable TLS encryption (recommended) |
| Skip TLS Verification | Disable certificate validation (not recommended for production) |

### Email content

Ban alerts include: IP address, jail name, hostname, failure count, country, whois data, and relevant log lines. The email uses an HTML template with two style variants (`modern` and `classic`, controlled by the `emailStyle` environment variable).

### Testing

Click **Send Test Email** in the UI after saving settings. The test email uses the same SMTP path as real alerts, so a successful test confirms the full delivery chain.

### Notes

- Office365 and Gmail typically require the `LOGIN` auth method (selected automatically by the `Auto` option).
- Emails include RFC-compliant `Message-ID` and `Date` headers to minimize spam classification. (but can still happen because of the log-content that is sended within a ban-mail.)

## Webhook

Sends a JSON payload to any HTTP endpoint. Compatible with ntfy, Matrix bridges, Slack/Mattermost incoming webhooks, Gotify, custom REST APIs, and any system that accepts JSON over HTTP.

### Settings

| Field | Description |
|---|---|
| Webhook URL | The target endpoint (e.g. `https://my-ntfy.example.com/fail2ban-alerts`) |
| HTTP Method | `POST` (default) or `PUT` |
| Custom Headers | One per line in `Key: Value` format. Useful for auth tokens, content-type overrides, or ntfy-specific headers like `Title` and `Priority` |
| Skip TLS Verification | Disable certificate validation for self-signed endpoints |

### Payload format

Every alert sends the following JSON body:

```json
{
  "event": "ban",
  "ip": "1.2.3.4",
  "jail": "sshd",
  "hostname": "webserver-01",
  "country": "CN",
  "failures": "5",
  "whois": "...",
  "logs": "...",
  "timestamp": "2026-02-23T12:00:00Z"
}
```

The `event` field is `"ban"`, `"unban"`, or `"test"` (for the test button).

### ntfy integration example

ntfy expects either plain text to a topic URL, or its own JSON format to the root URL. The simplest approach:

1. Set the Webhook URL to the **topic URL**: `https://my-ntfy.example.com/fail2ban-alerts`
2. Add custom headers for better notifications (optional):
   ```
   Title: Fail2ban Alert
   Priority: high
   Tags: rotating_light
   ```

The JSON payload will appear as the notification body. For ntfy with authentication, add an `Authorization: Bearer <token>` header.

### Slack / Mattermost example

For Slack or Mattermost incoming webhooks, the endpoint expects a `text` field. Since Fail2Ban UI sends a generic JSON payload, use a middleware or Slack workflow to parse it, or use a webhook-to-Slack bridge.

### Testing

Click **Send Test Webhook** after saving settings. This sends a test payload (`"event": "test"`) with a dummy IP (`203.0.113.1`) to verify connectivity.

### Technical details

- Timeout: 15 seconds per request.
- The `Content-Type` header is always set to `application/json`.
- Custom headers override any default header except `Content-Type`.
- TLS verification can be disabled for self-signed certificates.
- HTTP responses with status >= 400 are treated as errors and logged.

## Elasticsearch

Indexes ban/unban events as structured documents into Elasticsearch, using ECS (Elastic Common Schema) field names for native Kibana compatibility.

### Settings

| Field | Description |
|---|---|
| Elasticsearch URL | Cluster endpoint (e.g. `https://elasticsearch.example.com:9200`) |
| Index Name | Base name for the index (default: `fail2ban-events`). A daily suffix `-YYYY.MM.DD` is appended automatically. |
| API Key | Base64-encoded API key (preferred authentication). Leave empty for username/password auth. |
| Username | Basic auth username (used when API Key is empty) |
| Password | Basic auth password |
| Skip TLS Verification | Disable certificate validation for self-signed clusters |

### Document structure

Each event is indexed to `<index>-YYYY.MM.DD` (e.g. `fail2ban-events-2026.02.23`):

```json
{
  "@timestamp": "2026-02-23T12:00:00Z",
  "event.kind": "alert",
  "event.type": "ban",
  "source.ip": "1.2.3.4",
  "source.geo.country_iso_code": "CN",
  "observer.hostname": "webserver-01",
  "fail2ban.jail": "sshd",
  "fail2ban.failures": "5",
  "fail2ban.whois": "...",
  "fail2ban.logs": "..."
}
```

### Elasticsearch setup

**1. Create an index template**

In Kibana Dev Tools or via the API:

```
PUT _index_template/fail2ban
{
  "index_patterns": ["fail2ban-events-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "properties": {
        "@timestamp":                    { "type": "date" },
        "event.kind":                    { "type": "keyword" },
        "event.type":                    { "type": "keyword" },
        "source.ip":                     { "type": "ip" },
        "source.geo.country_iso_code":   { "type": "keyword" },
        "observer.hostname":             { "type": "keyword" },
        "fail2ban.jail":                 { "type": "keyword" },
        "fail2ban.failures":             { "type": "keyword" },
        "fail2ban.whois":                { "type": "text" },
        "fail2ban.logs":                 { "type": "text" }
      }
    }
  }
}
```

**2. Create an API key**

In Kibana: Stack Management → API Keys → Create API key. The key needs write access to `fail2ban-events-*` indices.

**3. Configure Fail2ban-UI**

Enter the Elasticsearch URL, index name, and API key in the Alert Settings. Save and click **Test Connection** to verify. The test creates the first document.

**4. Create a Kibana Data View**

In Kibana: Stack Management → Data Views → Create data view. Use `fail2ban-events-*` as the name and index pattern. Select `@timestamp` as the time field.

**5. Explore in Discover**

Go to Kibana Discover, select the `fail2ban-events-*` data view, and you should see your indexed events.

### Testing

**Test Connection** indexes a test document (`"event.type": "test"`) with a dummy IP. A successful test confirms authentication, network connectivity, and index write permissions.

### Technical details

- Authentication: API key (sent as `Authorization: ApiKey <key>`) or basic auth.
- Index naming: `<index>-YYYY.MM.DD` using the UTC date of the event.
- Timeout: 15 seconds per request.
- Documents are sent via `POST /<index>/_doc`.
- TLS verification can be disabled for self-signed clusters.
- HTTP responses with status >= 400 are treated as errors and logged.

## Alert dispatch flow

When a ban or unban event arrives via the Fail2Ban callback (and the pharsing was valid):

1. The event is stored in the database and broadcast via WebSocket (always, regardless of alerts).
2. The system checks whether alerts are enabled for the event type (ban/unban).
3. The IP is geolocated and checked against the configured alert countries.
4. If the country matches, the alert is dispatched to the configured provider.

```
Ban/Unban Event
  → Store in DB + WebSocket broadcast
  → Check alerts enabled?
  → Check country filter?
  → Dispatch to provider:
      ├── email         → sendBanAlert() → sendEmail() via SMTP
      ├── webhook       → sendWebhookAlert() → HTTP POST/PUT
      └── elasticsearch → sendElasticsearchAlert() → POST /<index>/_doc
```

Switching providers does not affect event storage or WebSocket broadcasting. Only the notification delivery channel changes.
