# Alert providers

Fail2Ban UI can send a notification whenever a ban or unban event occurs. Three providers are available: **Email (SMTP)**, **Webhook**, and **Elasticsearch**. Only one provider can be active at a time.

All providers share the same global settings:


| Setting                         | Description                                                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Enable alerts for bans / unbans | Master toggles that control whether any alert fires                                                              |
| Alert Countries                 | Only events for IPs geolocated to the selected countries trigger alerts. Set to `ALL` to alert on every country. |
| GeoIP Provider                  | How country lookups are performed: the built-in API or a local MaxMind database                                  |
| Maximum Log Lines               | Limits the number of log lines attached to alert payloads                                                        |


## Email (SMTP)

The default provider. Sends HTML-formatted emails through a configured SMTP server.

### Settings


| Field                 | Description                                                      |
| --------------------- | ---------------------------------------------------------------- |
| Destination Email     | Recipient address for all alert emails                           |
| SMTP Host             | Mail server hostname, for example `smtp.office365.com`           |
| SMTP Port             | Common values: 587 (STARTTLS), 465 (implicit TLS), 25 (plain)    |
| SMTP Username         | Login username for the mail server                               |
| SMTP Password         | Login password or app password                                   |
| Sender Email          | The `From:` address on outgoing alerts                           |
| Authentication Method | `Auto` (LOGIN preferred), `LOGIN`, `PLAIN`, or `CRAM-MD5`        |
| Use TLS               | Enables TLS encryption (recommended)                             |
| Skip TLS Verification | Disables certificate validation (not recommended for production) |


### Email content

Ban alerts include the IP address, jail name, hostname, failure count, country, Whois data, and the relevant log lines. The email uses an HTML template with two style variants, `modern` (default) and `classic`, controlled by the `emailStyle` environment variable.

### Testing

Click **Send Test Email** in the UI after saving the settings. The test email uses the same SMTP path as real alerts, so a successful test confirms the full delivery chain.

### Notes

- Office365 and Gmail typically require the `LOGIN` authentication method; the `Auto` option selects it automatically.
- Emails include RFC-compliant `Message-ID` and `Date` headers to improve deliverability.

## Webhook

Sends a JSON payload to any HTTP endpoint. Compatible with ntfy, Matrix bridges, Slack and Mattermost incoming webhooks, Gotify, custom REST APIs, and any system that accepts JSON over HTTP.

### Settings


| Field                 | Description                                                                                                                                    |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Webhook URL           | Target endpoint, for example `https://my-ntfy.example.com/fail2ban-alerts`                                                                     |
| HTTP Method           | `POST` (default) or `PUT`                                                                                                                      |
| Custom Headers        | One per line, in `Key: Value` format. Useful for auth tokens, content-type overrides, or ntfy-specific headers such as `Title` and `Priority`. |
| Skip TLS Verification | Disables certificate validation for self-signed endpoints                                                                                      |


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
  "timestamp": "2026-06-19T12:00:00Z"
}
```

The `event` field is `"ban"`, `"unban"`, or `"test"` (sent by the test button).

### ntfy integration

ntfy expects either plain text sent to a topic URL or its own JSON format sent to the root URL. The simplest approach:

1. Set the webhook URL to the *topic URL*: `https://my-ntfy.example.com/fail2ban-alerts`.
2. Optionally add custom headers for better notifications:
  ```
   Title: Fail2ban Alert
   Priority: high
   Tags: rotating_light
  ```

The JSON payload appears as the notification body. For protected ntfy instances, add an `Authorization: Bearer <token>` header.

### Slack / Mattermost

Slack and Mattermost incoming webhooks expect a `text` field. Since Fail2Ban UI sends a generic JSON payload, use middleware or a Slack workflow to parse it, or a webhook-to-Slack bridge.

### Telegram

The Telegram Bot API requires payload transformation (`chat_id`, `text`). Use a relay workflow, n8n, Node-RED, or a small custom service, to convert the generic payload into Telegram `sendMessage` format. See [webhooks.md](webhooks.md) for a worked example.

### Testing

Click **Send Test Webhook** after saving the settings. This sends a test payload (`"event": "test"`) with the dummy IP `203.0.113.1` to verify connectivity.

### Technical details

- Timeout: 15 seconds per request.
- Default `Content-Type` is `application/json`.
- Custom headers are applied after the defaults and can override them, including `Content-Type`, if the receiver requires it.
- TLS verification can be disabled for self-signed certificates.
- HTTP responses with status `>= 400` are treated as errors and logged.

## Elasticsearch

Writes ban and unban events to an Elasticsearch data stream as structured documents, using ECS (Elastic Common Schema) field names for native Kibana compatibility. A data stream rolls its backing indices over and deletes them through its lifecycle policy, so events never pile up in one ever-growing index. Requires Elasticsearch 8.13 or later.

### Settings


| Field                 | Description                                                                                                                                                                              |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Elasticsearch URL     | Cluster endpoint, for example `https://elasticsearch.example.com:9200`                                                                                                                   |
| Data Stream           | Target data stream (default: `logs-fail2ban_ui.events-default`). The default matches the built-in `logs-*-*` template. A custom name needs an index template with data streams enabled. |
| API Key               | Base64-encoded API key (preferred authentication). Leave empty for username/password auth.                                                                                               |
| Username              | Basic auth username, used when API Key is empty                                                                                                                                          |
| Password              | Basic auth password                                                                                                                                                                      |
| Skip TLS Verification | Disables certificate validation for self-signed clusters                                                                                                                                 |


### Document structure

Each event is written to the configured data stream, for example `logs-fail2ban_ui.events-default`. Elasticsearch stores it in hidden backing indices such as `.ds-logs-fail2ban_ui.events-default-2026.09.30-000001`.

When the name follows the `logs-<dataset>-<namespace>` scheme, each document also carries `data_stream.type`, `data_stream.dataset`, and `data_stream.namespace`, so Kibana can filter events by dataset.

The raw `fail2ban.logs` and `fail2ban.whois` fields are always present. In addition, Fail2Ban UI parses both fields - logs through grok patterns, Whois through regular expressions - and extracts structured, searchable ECS fields. The enrichment is best-effort: if a log format is not recognized, only the raw text is indexed.

**Core fields:**

```json
{
  "@timestamp": "2026-06-19T12:00:00Z",
  "event.kind": "alert",
  "event.type": "ban",
  "source.ip": "1.2.3.4",
  "source.geo.country_iso_code": "CN",
  "observer.hostname": "webserver-01",
  "fail2ban.jail": "sshd",
  "fail2ban.failures": "5",
  "fail2ban.whois": "...",
  "fail2ban.logs": "...",
  "data_stream.type": "logs",
  "data_stream.dataset": "fail2ban_ui.events",
  "data_stream.namespace": "default"
}
```

**Normalized fields from `fail2ban.logs`** (present only when log parsing succeeds):


| Field                       | Type    | Description                                                                         |
| --------------------------- | ------- | ----------------------------------------------------------------------------------- |
| `event.action`              | keyword | Action, for example `http_request`, `failed_password`, `invalid_user`, `http_error` |
| `log.timestamp`             | keyword | Timestamp extracted from the log line                                               |
| `log.level`                 | keyword | Log severity, for example `error`, `warn`                                           |
| `log.syslog.hostname`       | keyword | Hostname from the syslog prefix                                                     |
| `process.name`              | keyword | Service name, for example `sshd`, `nginx`, `apache`                                 |
| `process.pid`               | integer | Process ID                                                                          |
| `http.request.method`       | keyword | HTTP method (GET, POST, ...)                                                        |
| `http.response.status_code` | integer | HTTP response status                                                                |
| `http.response.body.bytes`  | integer | Response body size                                                                  |
| `http.version`              | keyword | HTTP protocol version                                                               |
| `http.request.referrer`     | keyword | HTTP referrer                                                                       |
| `url.original`              | keyword | Full request URL as seen in the log                                                 |
| `url.path`                  | keyword | URL path component                                                                  |
| `url.query`                 | text    | URL query string                                                                    |
| `user_agent.original`       | text    | Full user-agent string                                                              |
| `source.address`            | keyword | Client address from the log line                                                    |
| `source.port`               | integer | Client port (sshd connections)                                                      |
| `source.user.name`          | keyword | Target username (sshd attacks, HTTP auth)                                           |
| `server.address`            | keyword | Server or vhost name, when present in the log                                       |
| `message`                   | text    | Error message body (error logs)                                                     |
| `fail2ban.parsed_logs`      | nested  | Array of individually parsed log lines (multi-line events)                          |


**Normalized fields from `fail2ban.whois`** (present only when WHOIS parsing succeeds):


| Field                     | Type    | Description                                          |
| ------------------------- | ------- | ---------------------------------------------------- |
| `whois.net_range`         | keyword | Network range, for example `45.3.32.0 - 45.3.63.255` |
| `whois.cidr`              | keyword | CIDR notation, for example `45.3.32.0/19`            |
| `whois.net_name`          | keyword | Network name                                         |
| `whois.org_name`          | text    | Organization name                                    |
| `whois.org_id`            | keyword | Organization ID                                      |
| `whois.country`           | keyword | Country from the WHOIS record                        |
| `whois.abuse_email`       | keyword | Abuse contact email                                  |
| `whois.abuse_phone`       | keyword | Abuse contact phone                                  |
| `whois.asn`               | keyword | Autonomous system number                             |
| `whois.registration_date` | keyword | Registration date                                    |
| `whois.updated_date`      | keyword | Last update date                                     |


**Currently supported log formats** (parsed via grok patterns):


| Format                                               | Example jail names             |
| ---------------------------------------------------- | ------------------------------ |
| Apache/Nginx combined, with or without vhost prefix  | `apache-`*, `nginx-*`, `npm-*` |
| Apache error log (2.0 and 2.4)                       | `apache-*`                     |
| Nginx error log                                      | `nginx-*`                      |
| sshd: failed password, invalid user, disconnect, PAM | `sshd`, `ssh-*`                |
| Postfix: reject, SASL auth failure                   | `postfix-*`                    |
| Dovecot: auth failure                                | `dovecot-*`                    |
| Generic syslog (fallback)                            | any                            |


The jail name is used as a hint to prioritize pattern matching - an `sshd` jail tries the SSH patterns first - but all patterns are tried if the primary category does not match.

### Elasticsearch setup

#### 1. Create an index template (recommended)

The default data stream works without a template, because the built-in `logs-*-*` template matches it. That template maps fields dynamically, though: `log.timestamp` becomes a date field and drops the raw log timestamps, long `fail2ban.logs` values stay unsearchable, and `fail2ban.parsed_logs` loses its per-line grouping. The following template keeps the built-in logs settings and lifecycle and adds the exact field types.

Run it in Kibana Dev Tools before the first event arrives. Mappings apply only to backing indices created afterwards.

```
PUT _index_template/logs-fail2ban_ui.events
{
  "index_patterns": ["logs-fail2ban_ui.events-*"],
  "data_stream": {},
  "priority": 200,
  "composed_of": ["logs@mappings", "logs@settings", "logs@custom", "logs-fail2ban_ui.events@custom", "ecs@mappings"],
  "ignore_missing_component_templates": ["logs@custom", "logs-fail2ban_ui.events@custom"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp":                  { "type": "date" },
        "event.kind":                  { "type": "keyword" },
        "event.type":                  { "type": "keyword" },
        "event.action":                { "type": "keyword" },
        "source.ip":                   { "type": "ip" },
        "source.address":              { "type": "keyword" },
        "source.port":                 { "type": "integer" },
        "source.user.name":            { "type": "keyword" },
        "source.geo.country_iso_code": { "type": "keyword" },
        "observer.hostname":           { "type": "keyword" },
        "server.address":              { "type": "keyword" },
        "http.request.method":         { "type": "keyword" },
        "http.response.status_code":   { "type": "integer" },
        "http.response.body.bytes":    { "type": "long" },
        "http.request.referrer":       { "type": "keyword" },
        "http.version":                { "type": "keyword" },
        "url.original":                { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 }}},
        "url.path":                    { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 }}},
        "url.query":                   { "type": "text" },
        "user_agent.original":         { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 512 }}},
        "process.name":                { "type": "keyword" },
        "process.pid":                 { "type": "integer" },
        "log.timestamp":               { "type": "keyword" },
        "log.level":                   { "type": "keyword" },
        "log.syslog.hostname":         { "type": "keyword" },
        "message":                     { "type": "text" },
        "fail2ban.jail":               { "type": "keyword" },
        "fail2ban.failures":           { "type": "keyword" },
        "fail2ban.whois":              { "type": "text" },
        "fail2ban.logs":               { "type": "text" },
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
        "whois.net_range":             { "type": "keyword" },
        "whois.cidr":                  { "type": "keyword" },
        "whois.net_name":              { "type": "keyword" },
        "whois.org_name":              { "type": "text", "fields": { "keyword": { "type": "keyword" }}},
        "whois.org_id":                { "type": "keyword" },
        "whois.country":               { "type": "keyword" },
        "whois.abuse_email":           { "type": "keyword" },
        "whois.abuse_phone":           { "type": "keyword" },
        "whois.asn":                   { "type": "keyword" },
        "whois.registration_date":     { "type": "keyword" },
        "whois.updated_date":          { "type": "keyword" }
      }
    }
  }
}
```

To change the retention for Fail2Ban UI events only, put the lifecycle policy in the optional `logs-fail2ban_ui.events@custom` component template, which the template above already includes. The policy must contain a rollover action:

```
PUT _component_template/logs-fail2ban_ui.events@custom
{
  "template": {
    "settings": { "index.lifecycle.name": "<your-policy>" }
  }
}
```

Without it, the events inherit the `logs` policy, or the policy set in `logs@custom`.

#### 2. Create an API key

Give the key only the privileges that Fail2Ban UI needs: `create_doc` appends events but can't read, change or delete them, and `auto_configure` lets the first event create the data stream and lets new fields extend the mapping.

In Kibana Dev Tools:

```
POST _security/api_key
{
  "name": "fail2ban-ui",
  "role_descriptors": {
    "fail2ban_ui_writer": {
      "indices": [
        { "names": ["logs-fail2ban_ui.events-*"], "privileges": ["create_doc", "auto_configure"] }
      ]
    }
  }
}
```

Copy the `encoded` value from the response. If you use a custom data stream name, adjust `names` to match it.

#### 3. Configure Fail2Ban UI

Enter the Elasticsearch URL, data stream, and API key under **Settings -> Alert Settings**. Save and click **Test Connection** to verify. The test event creates the data stream if it does not exist yet.

#### 4. Create a Kibana data view

In Kibana: **Stack Management -> Data Views -> Create data view**. Use `logs-fail2ban_ui.events-*` as the name and index pattern, and select `@timestamp` as the time field.

#### 5. Explore in Discover

Open Kibana Discover and select the `logs-fail2ban_ui.events-*` data view. The events appear there.

### Upgrading from daily indices

Earlier releases wrote to daily indices named `fail2ban-events-YYYY.MM.DD`. On upgrade, a stored index name of `fail2ban-events`, the old default, switches to `logs-fail2ban_ui.events-default` automatically. A custom index name is kept and must now name a data stream; otherwise every alert fails with a "not a data stream" error.

1. Create a new API key as described in [Create an API key](#2-create-an-api-key). A key restricted to `fail2ban-events-*` can't write to the data stream. If you use a role, add `logs-fail2ban_ui.events-*` with `create_doc` and `auto_configure` to it.
2. Optional: create the index template before the first event.
3. Save the new key under **Settings -> Alert Settings** and click **Test Connection**.
4. To see old and new events together, create a data view with the index pattern `logs-fail2ban_ui.events-*,fail2ban-events-*`. The field types of the template above match the old daily indices, so the combined view has no field conflicts.

The old daily indices stay until you delete them or their lifecycle policy removes them. To move their events into the data stream instead, reindex them. Data streams accept only `create` operations:

```
POST _reindex
{
  "source": { "index": "fail2ban-events-*" },
  "dest": { "index": "logs-fail2ban_ui.events-default", "op_type": "create" }
}
```

### Testing

**Test Connection** writes a test event (`"event.type": "test"`) with a dummy IP. A successful test confirms authentication, network connectivity, and write permissions on the data stream.

### Technical details

- Authentication: API key (sent as `Authorization: ApiKey <key>`) or basic auth.
- Target: a data stream. Documents are sent through `POST /<data stream>/_doc?require_data_stream=true`, so Elasticsearch refuses the write instead of creating a plain index when no data stream template matches the name.
- Timeout: 15 seconds per request.
- TLS verification can be disabled for self-signed clusters.
- HTTP responses with status `>= 400` are treated as errors and logged.

## Alert dispatch flow

When a ban or unban event arrives through the Fail2Ban callback and payload validation succeeds:

1. The event is stored in the database and broadcast over WebSocket - always, regardless of alert settings.
2. The system checks whether alerts are enabled for the event type (ban or unban).
3. The IP is geolocated and checked against the configured alert countries.
4. If the country matches, the alert is dispatched to the configured provider.

```
Ban/unban event
  -> store in DB + WebSocket broadcast
  -> alerts enabled for this event type?
  -> country filter matches?
  -> dispatch to provider:
      +-- email         -> sendBanAlert() -> sendEmail() via SMTP
      +-- webhook       -> sendWebhookAlert() -> HTTP POST/PUT
      \-- elasticsearch -> enrich logs (grok) + enrich whois (regex)
                          -> sendElasticsearchAlert() -> POST /<data stream>/_doc
```

Switching providers does not affect event storage or WebSocket broadcasting; only the notification delivery channel changes.

## Adding new log format patterns

Log format patterns are defined in `internal/enrichment/patterns.go`. To add support for a new log format:

1. Add a `PatternDef` entry to the appropriate category slice: `HTTPPatterns`, `SSHPatterns`, `MailPatterns`, or `FallbackPatterns`.
2. Write the pattern in standard grok syntax with ECS field names in the capture groups, for example `%{IP:source.address}`.
3. Set the `Action` field to a normalized event action name.
4. Set the `Process` field to the service name; it is used as a fallback when the name is not captured from the log.

No other files need to change. The parser compiles all patterns at startup and tries them automatically.