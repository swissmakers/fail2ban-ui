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
- Emails include RFC-compliant `Message-ID` and `Date` headers to improve deliverability.

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

### Telegram example

Telegram Bot API usually requires payload transformation (`chat_id`, `text`). Use a relay workflow (n8n, Node-RED, custom service) to convert Fail2Ban UI's generic JSON payload into Telegram `sendMessage` format.

### Testing

Click **Send Test Webhook** after saving settings. This sends a test payload (`"event": "test"`) with a dummy IP (`203.0.113.1`) to verify connectivity.

### Technical details

- Timeout: 15 seconds per request.
- Default `Content-Type` is `application/json`.
- Custom headers are applied after defaults and can override default headers (including `Content-Type`) if required by the receiver.
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

Each event is indexed to `<index>-YYYY.MM.DD` (e.g. `fail2ban-events-2026.02.23`).

The raw `fail2ban.logs` and `fail2ban.whois` fields will keep present. Additionally, Fail2Ban UI automatically parses these fields using grok patterns and extracts structured, searchable ECS fields. The enrichment is currently best-effort: if a log format is not recognised, only the raw text is indexed.

**Core fields**:

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

**Normalized fields from `fail2ban.logs`** (only present when log parsing succeeds):

| Field | Type | Description |
|---|---|---|
| `event.action` | keyword | Action (e.g. `http_request`, `failed_password`, `invalid_user`, `http_error`) |
| `log.timestamp` | keyword | Timestamp extracted from the log line |
| `log.level` | keyword | Log severity (e.g. `error`, `warn`) |
| `log.syslog.hostname` | keyword | Hostname from syslog prefix |
| `process.name` | keyword | Service name (e.g. `sshd`, `nginx`, `apache`) |
| `process.pid` | integer | Process ID |
| `http.request.method` | keyword | HTTP method (GET, POST, etc.) |
| `http.response.status_code` | integer | HTTP response status |
| `http.response.body.bytes` | integer | Response body size |
| `http.version` | keyword | HTTP protocol version |
| `http.request.referrer` | keyword | HTTP referrer |
| `url.original` | keyword | Full request URL as seen in the log |
| `url.path` | keyword | URL path component |
| `url.query` | text | URL query string |
| `user_agent.original` | text | Full user-agent string |
| `source.address` | keyword | Client address from the log line |
| `source.port` | integer | Client port (sshd connections) |
| `source.user.name` | keyword | Target username (sshd attacks, HTTP auth) |
| `server.address` | keyword | Server/vhost name (when present in log) |
| `message` | text | Error message body (error logs) |
| `fail2ban.parsed_logs` | nested | Array of individually parsed log lines (multi-line events) |

**Normalized fields from `fail2ban.whois`** (only present when WHOIS parsing succeeds):

| Field | Type | Description |
|---|---|---|
| `whois.net_range` | keyword | Network range (e.g. `45.3.32.0 - 45.3.63.255`) |
| `whois.cidr` | keyword | CIDR notation (e.g. `45.3.32.0/19`) |
| `whois.net_name` | keyword | Network name |
| `whois.org_name` | text | Organisation name |
| `whois.org_id` | keyword | Organisation ID |
| `whois.country` | keyword | Country from WHOIS record |
| `whois.abuse_email` | keyword | Abuse contact email |
| `whois.abuse_phone` | keyword | Abuse contact phone |
| `whois.asn` | keyword | Autonomous System Number |
| `whois.registration_date` | keyword | Registration date |
| `whois.updated_date` | keyword | Last update date |

**Currently supported log formats** (parsed via grok patterns):

| Format | Example jail names |
|---|---|
| Apache/Nginx combined (with or without vhost prefix) | `apache-*`, `nginx-*`, `npm-*` |
| Apache error log (2.0 and 2.4) | `apache-*` |
| Nginx error log | `nginx-*` |
| sshd (failed password, invalid user, disconnect, PAM) | `sshd`, `ssh-*` |
| Postfix (reject, SASL auth failure) | `postfix-*` |
| Dovecot (auth failure) | `dovecot-*` |
| Generic syslog (fallback) | any |

The jail name is used as a hint to prioritise pattern matching (e.g. an `sshd` jail tries SSH patterns first), but all patterns are tried if the primary category does not match.

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
        "event.action":                  { "type": "keyword" },
        "source.ip":                     { "type": "ip" },
        "source.address":                { "type": "keyword" },
        "source.port":                   { "type": "integer" },
        "source.user.name":              { "type": "keyword" },
        "source.geo.country_iso_code":   { "type": "keyword" },
        "observer.hostname":             { "type": "keyword" },
        "server.address":                { "type": "keyword" },
        "http.request.method":           { "type": "keyword" },
        "http.response.status_code":     { "type": "integer" },
        "http.response.body.bytes":      { "type": "long" },
        "http.request.referrer":         { "type": "keyword" },
        "http.version":                  { "type": "keyword" },
        "url.original":                  { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 }}},
        "url.path":                      { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 }}},
        "url.query":                     { "type": "text" },
        "user_agent.original":           { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 512 }}},
        "process.name":                  { "type": "keyword" },
        "process.pid":                   { "type": "integer" },
        "log.timestamp":                 { "type": "keyword" },
        "log.level":                     { "type": "keyword" },
        "log.syslog.hostname":           { "type": "keyword" },
        "message":                       { "type": "text" },
        "fail2ban.jail":                 { "type": "keyword" },
        "fail2ban.failures":             { "type": "keyword" },
        "fail2ban.whois":                { "type": "text" },
        "fail2ban.logs":                 { "type": "text" },
        "fail2ban.parsed_logs": {
          "type": "nested",
          "properties": {
            "log.original":              { "type": "text" },
            "log.timestamp":             { "type": "keyword" },
            "server.address":            { "type": "keyword" },
            "source.address":            { "type": "keyword" },
            "source.user.name":          { "type": "keyword" },
            "source.port":               { "type": "integer" },
            "http.request.method":       { "type": "keyword" },
            "http.response.status_code": { "type": "integer" },
            "http.response.body.bytes":  { "type": "long" },
            "http.version":              { "type": "keyword" },
            "url.original":              { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 }}},
            "user_agent.original":       { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 512 }}},
            "log.level":                 { "type": "keyword" },
            "message":                   { "type": "text" }
          }
        },
        "whois.net_range":               { "type": "keyword" },
        "whois.cidr":                    { "type": "keyword" },
        "whois.net_name":                { "type": "keyword" },
        "whois.org_name":                { "type": "text", "fields": { "keyword": { "type": "keyword" }}},
        "whois.org_id":                  { "type": "keyword" },
        "whois.country":                 { "type": "keyword" },
        "whois.abuse_email":             { "type": "keyword" },
        "whois.abuse_phone":             { "type": "keyword" },
        "whois.asn":                     { "type": "keyword" },
        "whois.registration_date":       { "type": "keyword" },
        "whois.updated_date":            { "type": "keyword" }
      }
    }
  }
}
```

**Note:** If you already have an older index template, update/recreate it with the new mappings. Existing indices/documents are not modified retroactively; templates apply when new indices are created.

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

When a ban or unban event arrives via the Fail2Ban callback (and payload validation succeeds):

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
      └── elasticsearch → enrich logs (grok) + enrich whois (regex)
                          → sendElasticsearchAlert() → POST /<index>/_doc
```

Switching providers does not affect event storage or WebSocket broadcasting. Only the notification delivery channel changes.

### Adding new log format patterns

Log format patterns are defined in `internal/enrichment/patterns.go`. To add support for a new log format:

1. Add a `PatternDef` entry to the appropriate category slice (`HTTPPatterns`, `SSHPatterns`, `MailPatterns`, or `FallbackPatterns`)
2. The pattern uses standard grok syntax with ECS field names in the capture groups (e.g. `%{IP:source.address}`)
3. Set the `Action` field to a normalised event action name
4. Set the `Process` field to the service name (used as fallback if not captured from the log)

No changes to other files are needed. The parser compiles all patterns at startup and tries them automatically.
