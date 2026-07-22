# Threat intelligence

Fail2Ban UI can query external threat-intelligence sources for suspicious IPs. The feature is optional and disabled by default.

## What it does

* Adds a **Threat intelligence** modal in the dashboard and log views, opened by clicking an IP address.
* Queries the configured provider through the backend, not from the browser. This avoids CORS issues and keeps the API key out of the client.
* Normalizes the response as:
  * `provider`
  * `ip`
  * `fetchedAt`
  * `data` (the raw provider payload)
* Uses short-lived caching to reduce API pressure, and handles upstream rate limits.

## Supported providers

| Provider value | Service | API key field |
|----------------|---------|---------------|
| `none` | Disabled | none |
| `alienvault` | AlienVault OTX | `alienVaultApiKey` |
| `abuseipdb` | AbuseIPDB | `abuseIpDbApiKey` |

## Configuration

Under **Settings -> Alert Settings**:

1. If you do not have an API key yet, create one with the selected provider.
2. Set **Threat Intel Provider** to `AlienVault OTX` or `AbuseIPDB`.
3. Enter the matching API key.
4. Save the settings.

## API endpoint

`GET /api/threat-intel/:ip`

Behavior:

* Validates the `:ip` parameter server-side.
* Reads the provider and keys from the saved application settings.
* Calls the provider upstream from the backend, avoiding key exposure and CORS.
* Returns the provider payload wrapped in a consistent response schema.

Example success payload:

```json
{
  "provider": "abuseipdb",
  "ip": "103.74.116.73",
  "fetchedAt": "2026-03-08T08:49:00Z",
  "data": {
    "data": {
      "abuseConfidenceScore": 100,
      "countryCode": "VN",
      "countryName": "Viet Nam",
      "domain": "tadu.vn",
      "hostnames": [],
      "ipAddress": "103.74.116.73",
      "ipVersion": 4,
      "isPublic": true,
      "isTor": false,
      "isWhitelisted": false,
      "isp": "TaDu Joint Stock Company",
      "lastReportedAt": "2026-03-08T06:12:11+00:00",
      "numDistinctUsers": 105,
      "reports": [
        {
          "categories": [15, 21],
          "comment": "103.74.116.73 - - [08/Mar/2026:07:12:11 +0100] \"POST /wp-login.php HTTP/1.1\" ...",
          "reportedAt": "2026-03-08T06:12:11+00:00",
          "reporterCountryCode": "MT",
          "reporterCountryName": "Malta",
          "reporterId": 43106
        }
      ]
    }
  }
}
```

Error responses:

| Status | Meaning |
|--------|---------|
| `400` | Invalid IP or invalid provider configuration |
| `409` | Threat intelligence disabled (`provider=none`) |
| `429` | Rate limit reached and no stale cache available |
| `502` | Upstream provider request or payload error |

## Caching and rate-limit behavior

* Successful (`200`) responses are cached for **30 minutes** per `provider:ip`.
* If the upstream returns `429`:
  * the retry window is taken from the `Retry-After` header
  * the fallback retry window is **2 minutes** when the header is missing or invalid
* During an active retry window:
  * if cached data exists, stale data is returned with status `200`
  * if no cache exists, the endpoint returns `429` with a `retryAfter` field

Response headers:

| Header | Meaning |
|--------|---------|
| `X-Threat-Intel-Cache: hit` | Served from fresh cache |
| `X-Threat-Intel-Cache: stale` | Served from stale cache during provider backoff |

## UI rendering

The modal is provider-aware:

* **AlienVault OTX**
  * Pulse count and pulse details
  * Tags, MITRE technique labels, references
  * Related context: industries, adversaries, malware families
* **AbuseIPDB**
  * Abuse confidence score
  * Total reports, distinct users, last-reported timestamp
  * ISP, domain, usage type, and the public/Tor/whitelist flags
  * Recent reports and categories

## Troubleshooting

| Symptom | Resolution |
|---------|------------|
| "Threat intelligence is disabled" | Set the provider to `alienvault` or `abuseipdb` in settings and provide the matching API key |
| Missing API key error | Add the key for the selected provider and save again |
| Frequent `429` responses | Wait for the retry window and rely on the stale-cache behavior, or reduce query frequency. Check the subscription plan of your provider account. |
