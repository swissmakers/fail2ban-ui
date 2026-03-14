# Threat Intelligence

Fail2Ban UI can automatically query suspicious IPs with external threat-intel sources.
This feature is optional and is disabled by default.

## What it does

- Adds a **Threat intelligence** modal in the dashboard/log views for IPs. (link on IP-address itself)
- Queries the configured threat-intel provider through the backend (not from the browser -> avoid CORS).
- Normalizes the response as:
  - `provider`
  - `ip`
  - `fetchedAt`
  - `data` (raw provider payload)
- Uses short-lived caching (to reduce API pressure) and upstream rate-limit handling.

## Currently supported providers

| Provider value | Service | API key field |
|---|---|---|
| `none` | Disabled | none |
| `alienvault` | AlienVault OTX | `alienVaultApiKey` |
| `abuseipdb` | AbuseIPDB | `abuseIpDbApiKey` |

## Configure in UI

Go to **Settings -> Alert Settings**:

1. If you do not have an API key yet, create one with your selected provider.
2. Set **Threat Intel Provider** to `AlienVault OTX` or `AbuseIPDB`.
3. Enter the matching API key.
4. Save settings.

## API endpoint

- `GET /api/threat-intel/:ip`

Behavior:
- Validates the `:ip` payload server-side.
- Reads provider + keys from saved app settings.
- Calls provider upstream from backend to avoid key exposure (and CORS).
- Returns provider payload wrapped in a consistent response schema.

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
                    "categories": [
                        15,
                        21
                    ],
                    "comment": "103.74.116.73 - - [08/Mar/2026:07:12:11 +0100] \"POST /wp-login.php HTTP/1.1\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\"",
                    "reportedAt": "2026-03-08T06:12:11+00:00",
                    "reporterCountryCode": "MT",
                    "reporterCountryName": "Malta",
                    "reporterId": 43106
                },
            ],
            ...
        }
    }
}
```

Common error responses:
- `400` invalid IP or invalid provider configuration
- `409` threat intel disabled (`provider=none`)
- `429` rate limit reached and no stale cache available
- `502` upstream/provider request or payload error

## Caching and rate-limit behavior

- Successful (`200`) responses are cached for **30 minutes** per `provider:ip`.
- If upstream returns `429`:
  - retry window is taken from `Retry-After` header
  - fallback retry window is **2 minutes** if header is missing/invalid
- During active retry window:
  - if cached data exists, stale data is returned (`200`)
  - if no cache exists, returns `429` with `retryAfter`

Response headers:
- `X-Threat-Intel-Cache: hit` -> served from fresh cache
- `X-Threat-Intel-Cache: stale` -> served from stale cache during provider backoff

## UI rendering

The modal is provider-aware:

- **AlienVault OTX**
  - pulse count and pulse details
  - tags, MITRE technique labels, references
  - related context (industries, adversaries, malware families)

- **AbuseIPDB**
  - abuse confidence score
  - total reports, distinct users, last reported timestamp
  - ISP/domain/usage type/public/tor/whitelist flags
  - recent reports and categories

## Troubleshooting

- **"Threat intelligence is disabled"**
  - Set provider to `alienvault` or `abuseipdb` in settings + correct API key.

- **Missing API key error**
  - Add the key for the selected provider and save again.

- **Frequent 429 responses**
  - Wait for retry window, rely on stale cache behavior, or reduce query frequency -> check your account subscription plan of the API.
