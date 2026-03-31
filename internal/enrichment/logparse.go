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
	"log"
	"strings"
	"sync"

	grok "github.com/elastic/go-grok"
)

// =========================================================================
//  Types / Variables
// =========================================================================

type compiledPattern struct {
	def  PatternDef
	grok *grok.Grok
}

var (
	initOnce         sync.Once
	httpCompiled     []compiledPattern
	sshCompiled      []compiledPattern
	mailCompiled     []compiledPattern
	fallbackCompiled []compiledPattern
)

// Ensure the patterns are initialised.
func ensureInit() {
	initOnce.Do(func() {
		httpCompiled = compileAll(HTTPPatterns)
		sshCompiled = compileAll(SSHPatterns)
		mailCompiled = compileAll(MailPatterns)
		fallbackCompiled = compileAll(FallbackPatterns)
	})
}

func compileAll(defs []PatternDef) []compiledPattern {
	var out []compiledPattern
	for _, d := range defs {
		g := grok.New()
		if err := g.AddPatterns(SubPatterns); err != nil {
			log.Printf("⚠️ enrichment failed to add sub-patterns for %s: %v", d.Name, err)
			continue
		}
		if err := g.Compile(d.Pattern, true); err != nil {
			log.Printf("⚠️ enrichment failed to compile pattern %s: %v", d.Name, err)
			continue
		}
		out = append(out, compiledPattern{def: d, grok: g})
	}
	return out
}

// Parses the raw log text from a Fail2ban event and returns a map of structured fields.
func ParseLogLines(logs, jail string) map[string]interface{} {
	ensureInit()

	if strings.TrimSpace(logs) == "" {
		return nil
	}

	lines := splitAndClean(logs)
	if len(lines) == 0 {
		return nil
	}

	ordered := orderedPatterns(jail)

	var parsedEntries []map[string]interface{}
	var bestResult map[string]interface{}
	var bestDef PatternDef
	bestFieldCount := 0

	for _, line := range lines {
		result, def := parseLine(line, ordered)
		if result == nil {
			continue
		}
		result["log.original"] = line

		parsedEntries = append(parsedEntries, result)

		if len(result) > bestFieldCount {
			bestFieldCount = len(result)
			bestResult = result
			bestDef = def
		}
	}

	if bestResult == nil {
		return nil
	}

	enriched := make(map[string]interface{}, len(bestResult)+4)
	for k, v := range bestResult {
		if k == "log.original" {
			continue
		}
		enriched[k] = v
	}

	if bestDef.Action != "" {
		enriched["event.action"] = bestDef.Action
	}
	if _, ok := enriched["process.name"]; !ok && bestDef.Process != "" {
		enriched["process.name"] = bestDef.Process
	}

	postProcessFields(enriched)

	if len(parsedEntries) > 1 {
		enriched["fail2ban.parsed_logs"] = parsedEntries
	}

	return enriched
}

// =========================================================================
// Helper functions
// =========================================================================

// Splits the raw log text
func splitAndClean(logs string) []string {
	raw := strings.Split(logs, "\n")
	var out []string
	for _, l := range raw {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Returns compiled pattern slices in a priority order derived from the jail name.
// For example, an "sshd" jail tries SSH patterns first.
func orderedPatterns(jail string) [][]compiledPattern {
	jl := strings.ToLower(jail)

	switch {
	case containsAny(jl, "ssh"):
		return [][]compiledPattern{sshCompiled, httpCompiled, mailCompiled, fallbackCompiled}
	case containsAny(jl, "apache", "nginx", "http", "npm", "proxy", "web"):
		return [][]compiledPattern{httpCompiled, sshCompiled, mailCompiled, fallbackCompiled}
	case containsAny(jl, "postfix", "dovecot", "mail", "smtp", "imap", "pop3"):
		return [][]compiledPattern{mailCompiled, sshCompiled, httpCompiled, fallbackCompiled}
	default:
		return [][]compiledPattern{httpCompiled, sshCompiled, mailCompiled, fallbackCompiled}
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// Tries every compiled pattern in priority order and returns the first successful match.
func parseLine(line string, ordered [][]compiledPattern) (map[string]interface{}, PatternDef) {
	for _, group := range ordered {
		for _, cp := range group {
			result, err := cp.grok.ParseTypedString(line)
			if err != nil || len(result) == 0 {
				continue
			}
			cleanEmpty(result)
			if len(result) == 0 {
				continue
			}
			return result, cp.def
		}
	}
	return nil, PatternDef{}
}

// Removes keys whose value is empty or a dash placeholder.
func cleanEmpty(m map[string]interface{}) {
	for k, v := range m {
		if s, ok := v.(string); ok && (s == "" || s == "-") {
			delete(m, k)
		}
	}
}

// Performs secondary enrichment on the parsed fields.
func postProcessFields(m map[string]interface{}) {
	// Splits url.original into url.path and url.query
	if raw, ok := m["url.original"].(string); ok && raw != "" {
		if idx := strings.IndexByte(raw, '?'); idx >= 0 {
			m["url.path"] = raw[:idx]
			m["url.query"] = raw[idx+1:]
		} else {
			m["url.path"] = raw
		}
	}

	// Normalises common log.level values to lowercase
	if lv, ok := m["log.level"].(string); ok {
		m["log.level"] = strings.ToLower(lv)
	}
}
