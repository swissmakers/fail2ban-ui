// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the PolyForm Shield License 1.0.0.
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://polyformproject.org/licenses/shield/1.0.0/
//
//     or in the LICENSE file in this repository.
//
// Required Notice: Copyright Swissmakers GmbH (https://swissmakers.ch)

package enrichment

import (
	"regexp"
	"strings"
)

// =========================================================================
//  Types / Variables
// =========================================================================

// Maps raw whois keys (both ARIN and RIPE formats) to the normalised ECS-style output fields.
// When the same output field appears more than once the LAST match wins, which naturally prefers the more specific RIPE/regional record over the ARIN referral header.
var whoisKeyMap = map[string]string{
	// ARIN
	"netrange":      "whois.net_range",
	"cidr":          "whois.cidr",
	"netname":       "whois.net_name",
	"orgname":       "whois.org_name",
	"orgid":         "whois.org_id",
	"country":       "whois.country",
	"orgabuseemail": "whois.abuse_email",
	"orgabusephone": "whois.abuse_phone",
	"originas":      "whois.asn",
	"regdate":       "whois.registration_date",
	"updated":       "whois.updated_date",

	// RIPE / APNIC
	"inetnum":       "whois.net_range",
	"inet6num":      "whois.net_range",
	"org-name":      "whois.org_name",
	"organisation":  "whois.org_id",
	"org":           "whois.org_id",
	"origin":        "whois.asn",
	"created":       "whois.registration_date",
	"last-modified": "whois.updated_date",
	"route":         "whois.cidr",
	"route6":        "whois.cidr",
}

// Extracts the abuse contact email from the RIPE comment line:
// % Abuse contact for '...' is 'abuse@example.com'
var ripeAbuseRe = regexp.MustCompile(`(?i)abuse contact for .+ is '([^']+)'`)

// Matches "Key:  value" lines in whois output (supports both CamelCase ARIN keys and lower-case-hyphenated RIPE keys).
var kvLineRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_-]*):\s+(.+)$`)

// =========================================================================
//  Functions
// =========================================================================

// Parses WHOIS text into structured fields.
// Handles ARIN, RIPE, APNIC, LACNIC and AfriNIC formats.
// Fields that cannot be extracted are omitted.
func ParseWhois(whois string) map[string]interface{} {
	if strings.TrimSpace(whois) == "" {
		return nil
	}

	result := make(map[string]interface{})
	seenKeys := make(map[string]bool)

	for _, line := range strings.Split(whois, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Checks for RIPE-style abuse contact comment
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			if m := ripeAbuseRe.FindStringSubmatch(line); len(m) == 2 {
				result["whois.abuse_email"] = strings.TrimSpace(m[1])
			}
			continue
		}

		m := kvLineRe.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}

		rawKey := strings.TrimSpace(m[1])
		rawVal := strings.TrimSpace(m[2])

		lookupKey := strings.ToLower(rawKey)

		outField, known := whoisKeyMap[lookupKey]
		if !known {
			continue
		}
		if outField == "whois.abuse_email" && seenKeys[outField] {
			continue
		}
		result[outField] = rawVal
		seenKeys[outField] = true
	}

	// Normalises the ASN: strips "AS" prefix if present (e.g. "AS200373" → "200373")
	if asn, ok := result["whois.asn"].(string); ok {
		asn = strings.TrimSpace(asn)
		if strings.HasPrefix(strings.ToUpper(asn), "AS") {
			result["whois.asn"] = asn[2:]
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}
