// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

var (
	httpQuotedStatusPattern = regexp.MustCompile(`"[^"]*"\s+(\d{3})\b`)
	httpPlainStatusPattern  = regexp.MustCompile(`\s(\d{3})\s+(?:\d+|-)`)
	suspiciousLogIndicators = []string{
		"select ",
		"union ",
		"/etc/passwd",
		"/xmlrpc.php",
		"/wp-admin",
		"/cgi-bin",
		"cmd=",
		"wget",
		"curl ",
		"nslookup",
		"content-length: 0",
		"${",
	}
	localeCache     = make(map[string]map[string]string)
	localeCacheLock sync.RWMutex
)

type emailDetail struct {
	Label string
	Value string
}

// Filters relevant logs for the email alert to show relevant lines.
func filterRelevantLogs(logs, ip string, maxLines int) string {
	if logs == "" {
		return ""
	}
	if maxLines <= 0 {
		maxLines = 50
	}
	lines := strings.Split(logs, "\n")
	if len(lines) <= maxLines {
		return logs
	}
	// Priority patterns to identify relevant log lines
	priorityPatterns := []string{
		"denied", "deny", "forbidden", "unauthorized", "failed", "failure",
		"error", "403", "404", "401", "500", "502", "503",
		"invalid", "rejected", "blocked", "ban",
	}
	type scoredLine struct {
		line  string
		score int
		index int
	}
	scored := make([]scoredLine, len(lines))
	for i, line := range lines {
		lineLower := strings.ToLower(line)
		score := 0

		if strings.Contains(line, ip) {
			score += 10
		}
		for _, pattern := range priorityPatterns {
			if strings.Contains(lineLower, pattern) {
				score += 5
			}
		}
		score += (len(lines) - i) / 10
		scored[i] = scoredLine{
			line:  line,
			score: score,
			index: i,
		}
	}
	sort.SliceStable(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})
	selected := scored[:maxLines]
	sort.SliceStable(selected, func(i, j int) bool {
		return selected[i].index < selected[j].index
	})
	result := make([]string, len(selected))
	for i, s := range selected {
		result[i] = s.line
	}
	filtered := []string{}
	lastLine := ""
	for _, line := range result {
		if line != lastLine {
			filtered = append(filtered, line)
			lastLine = line
		}
	}
	return strings.Join(filtered, "\n")
}

// =========================================================================
//  Email Alerts and SMTP
// =========================================================================

// loadLocale returns cached translations for the given language, loading from disk if needed.
func loadLocale(lang string) (map[string]string, error) {
	localeCacheLock.RLock()
	if cached, ok := localeCache[lang]; ok {
		localeCacheLock.RUnlock()
		return cached, nil
	}
	localeCacheLock.RUnlock()

	data, err := fs.ReadFile(LocalesFS, lang+".json")
	if err != nil {
		// Falls back to English if the locale file is not found
		if lang != "en" {
			return loadLocale("en")
		}
		return nil, fmt.Errorf("failed to read locale file: %w", err)
	}

	var translations map[string]string
	if err := json.Unmarshal(data, &translations); err != nil {
		return nil, fmt.Errorf("failed to parse locale file: %w", err)
	}

	localeCacheLock.Lock()
	localeCache[lang] = translations
	localeCacheLock.Unlock()

	return translations, nil
}

// Resolves a translation key, falling back to English.
func getEmailTranslation(lang, key string) string {
	translations, err := loadLocale(lang)
	if err != nil {
		if lang != "en" {
			translations, err = loadLocale("en")
			if err != nil {
				return key
			}
		} else {
			return key
		}
	}

	if translation, ok := translations[key]; ok {
		return translation
	}

	if lang != "en" {
		enTranslations, err := loadLocale("en")
		if err == nil {
			if enTranslation, ok := enTranslations[key]; ok {
				return enTranslation
			}
		}
	}
	return key
}

// Reads the email template style from environment variable (default: "modern").
func getEmailStyle() string {
	style := os.Getenv("emailStyle")
	if style == "classic" {
		return "classic"
	}
	return "modern"
}

// Connects to the SMTP server and delivers a single HTML message.
func sendEmail(to, subject, body string, settings config.AppSettings) error {
	recipients := shared.SplitCommaList(to)
	if len(recipients) == 0 {
		log.Printf("WARNING: sendEmail skipped: no recipients provided.")
		return nil
	}

	// Skips sending if every recipient is still the default placeholder
	allPlaceholder := true
	for _, r := range recipients {
		if !strings.EqualFold(r, "alerts@example.com") {
			allPlaceholder = false
			break
		}
	}
	if allPlaceholder {
		log.Printf("WARNING: sendEmail skipped: all recipients are still the default placeholder (alerts@example.com). Please update the 'Destination Email' in Settings -> Alert Settings.")
		return nil
	}

	needsAuth := settings.SMTP.AuthMethod != "none"
	if settings.SMTP.Host == "" || settings.SMTP.From == "" || (needsAuth && (settings.SMTP.Username == "" || settings.SMTP.Password == "")) {
		err := errors.New("SMTP settings are incomplete. Please configure all required fields")
		log.Printf("ERROR: sendEmail validation failed: %v (Host: %q, Username: %q, From: %q)", err, settings.SMTP.Host, settings.SMTP.Username, settings.SMTP.From)
		return err
	}

	if settings.SMTP.Port <= 0 || settings.SMTP.Port > 65535 {
		err := errors.New("SMTP port must be between 1 and 65535")
		log.Printf("ERROR: sendEmail validation failed: %v (Port: %d)", err, settings.SMTP.Port)
		return err
	}

	fromHeader := sanitizeHeaderValue(settings.SMTP.From)
	// Build the To header with all recipients, comma-space separated
	toHeader := sanitizeHeaderValue(strings.Join(recipients, ", "))
	msgID := sanitizeHeaderValue(fmt.Sprintf("<%d.%s@fail2ban-ui>", time.Now().UnixNano(), settings.SMTP.From))
	subjectHeader := mime.QEncoding.Encode("UTF-8", subject)
	message := "From: " + fromHeader + "\r\n" +
		"To: " + toHeader + "\r\n" +
		"Subject: " + subjectHeader + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"Message-ID: " + msgID + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
		"\r\n" + body
	msg := []byte(message)

	smtpHost := settings.SMTP.Host
	smtpPort := settings.SMTP.Port
	smtpAddr := net.JoinHostPort(smtpHost, fmt.Sprintf("%d", smtpPort))

	tlsConfig := &tls.Config{
		ServerName:         smtpHost,
		InsecureSkipVerify: settings.SMTP.InsecureSkipVerify,
	}

	authMethod := settings.SMTP.AuthMethod
	if authMethod == "" {
		authMethod = "auto"
	}
	auth, err := getSMTPAuth(settings.SMTP.Username, settings.SMTP.Password, authMethod, smtpHost)
	if err != nil {
		log.Printf("ERROR: sendEmail: failed to create SMTP auth (method: %q): %v", authMethod, err)
		return fmt.Errorf("failed to create SMTP auth: %w", err)
	}
	log.Printf("sendEmail: Using SMTP auth method: %q, host: %s, port: %d, useTLS: %v, insecureSkipVerify: %v", authMethod, smtpHost, smtpPort, settings.SMTP.UseTLS, settings.SMTP.InsecureSkipVerify)

	// Port 465 uses implicit TLS (SMTPS); all other ports use plain SMTP with optional STARTTLS.
	useImplicitTLS, useSTARTTLS := smtpTLSMode(smtpPort, settings.SMTP.UseTLS)

	var client *smtp.Client

	if useImplicitTLS {
		conn, err := tls.Dial("tcp", smtpAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect via TLS: %w", err)
		}
		defer conn.Close()

		client, err = smtp.NewClient(conn, smtpHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
	} else {
		conn, err := net.DialTimeout("tcp", smtpAddr, 30*time.Second)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer conn.Close()

		client, err = smtp.NewClient(conn, smtpHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}

		if useSTARTTLS {
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("failed to start TLS: %w", err)
			}
		}
	}

	defer func() {
		if client != nil {
			client.Quit()
		}
	}()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			log.Printf("ERROR: sendEmail: SMTP authentication failed: %v", err)
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
		log.Printf("sendEmail: SMTP authentication successful")
	}

	err = sendSMTPMessage(client, settings.SMTP.From, recipients, msg)
	if err != nil {
		log.Printf("ERROR: sendEmail: Failed to send message: %v", err)
		return err
	}
	log.Printf("sendEmail: Successfully sent email to %s", strings.Join(recipients, ", "))
	return nil
}

// Sends the actual message
// Performs the MAIL/RCPT/DATA sequence on an open SMTP connection.
func sendSMTPMessage(client *smtp.Client, from string, recipients []string, msg []byte) error {
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	for _, r := range recipients {
		if err := client.Rcpt(r); err != nil {
			return fmt.Errorf("failed to set recipient %q: %w", r, err)
		}
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to start data command: %w", err)
	}
	defer wc.Close()
	if _, err = wc.Write(msg); err != nil {
		return fmt.Errorf("failed to write email content: %w", err)
	}
	client.Quit()
	return nil
}

// Builds paragraph-based details for the classic email template.
func renderClassicEmailDetails(details []emailDetail) string {
	if len(details) == 0 {
		return `<p>No metadata available.</p>`
	}
	var b strings.Builder
	for _, d := range details {
		b.WriteString(`<p><span class="label">`)
		b.WriteString(html.EscapeString(d.Label))
		b.WriteString(`:</span> `)
		b.WriteString(html.EscapeString(d.Value))
		b.WriteString(`</p>`)
		b.WriteString("\n")
	}
	return b.String()
}

// Renders the original email template layout.
func buildClassicEmailBody(title, intro string, details []emailDetail, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText, supportEmail string) string {
	detailRows := renderClassicEmailDetails(details)
	year := time.Now().Year()
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 20px auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0px 2px 4px rgba(0,0,0,0.1); }
    .header { text-align: center; padding-bottom: 10px; border-bottom: 2px solid #005DE0; }
    .header img { max-width: 150px; }
    .header h2 { color: #005DE0; margin: 10px 0; font-size: 24px; }
    .content { padding: 15px; }
    .details { background: #f9f9f9; padding: 15px; border-left: 4px solid #5579f8; margin-bottom: 10px; }
    .footer { text-align: center; color: #888; font-size: 12px; padding-top: 10px; border-top: 1px solid #ddd; margin-top: 15px; }
    .footer a { color: #005DE0; text-decoration: none; }
    .footer a:hover { color: #0044b3; text-decoration: underline; }
    .label { font-weight: bold; color: #333; }
    a { color: #005DE0; text-decoration: none; }
    a:hover { color: #0044b3; text-decoration: underline; }
    pre {
        background: #222;
        color: #ddd;
        font-family: "Courier New", Courier, monospace;
        font-size: 12px;
        padding: 10px;
        border-radius: 5px;
        overflow-x: auto;
        white-space: pre-wrap;
    }
    @media screen and (max-width: 600px) {
        .container { width: 90%%; padding: 10px; }
        .header h2 { font-size: 20px; }
        .details p { font-size: 14px; }
        .footer { font-size: 10px; }
    }
</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="https://swissmakers.ch/wp-content/uploads/2023/09/cyber.png" alt="Swissmakers GmbH" width="150" />
            <h2>ALERT: %s</h2>
        </div>
        <div class="content">
            <p>%s</p>
            <div class="details">
                %s
            </div>
            <h3>%s</h3>
            %s
            <h3>%s</h3>
            %s
        </div>
        <div class="footer">
            <p>%s</p>
            <p>For security inquiries, contact <a href="mailto:%s">%s</a></p>
            <p>&copy; %d Swissmakers GmbH. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(intro), detailRows, html.EscapeString(whoisTitle), whoisHTML, html.EscapeString(logsTitle), logsHTML, html.EscapeString(footerText), html.EscapeString(supportEmail), html.EscapeString(supportEmail), year)
}

// Renders the LOTR-themed email template.
func buildLOTREmailBody(title, intro string, details []emailDetail, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText string) string {
	detailRows := renderEmailDetails(details)
	year := strconv.Itoa(time.Now().Year())
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>%s</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { margin:0; padding:0; background: linear-gradient(135deg, #0d2818 0%%, #1a4d2e 50%%, #2d0a4f 100%%); font-family: Georgia, "Times New Roman", serif; color:#f4e8d0; line-height:1.6; -webkit-font-smoothing:antialiased; }
    .email-wrapper { width:100%%; padding:20px 10px; background: linear-gradient(135deg, #0d2818 0%%, #1a4d2e 50%%, #2d0a4f 100%%); }
    .email-container { max-width:640px; margin:0 auto; background:#f4e8d0; border:4px solid #d4af37; border-radius:12px; box-shadow:0 8px 32px rgba(0,0,0,0.6), inset 0 0 40px rgba(212,175,55,0.1); overflow:hidden; position:relative; }
    .email-container::before { content:''; position:absolute; top:0; left:0; right:0; bottom:0; background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(139,115,85,0.03) 2px, rgba(139,115,85,0.03) 4px); pointer-events:none; }
    .email-header { background: linear-gradient(180deg, #c1121f 0%%, #ff6b35 30%%, #d4af37 70%%, #1a4d2e 100%%); color:#ffffff; padding:40px 28px; text-align:center; position:relative; overflow:hidden; }
    .email-header::before { content:''; position:absolute; top:0; left:0; right:0; bottom:0; background: radial-gradient(circle at center, rgba(255,255,255,0.1) 0%%, transparent 70%%); animation: fireFlicker 3s ease-in-out infinite; }
    @keyframes fireFlicker { 0%%,100%% { opacity:0.6; } 50%% { opacity:1; } }
    .email-header-brand { margin:0 0 12px; font-size:12px; letter-spacing:0.4em; text-transform:uppercase; opacity:0.9; font-weight:600; font-family:'Cinzel', serif; position:relative; z-index:1; }
    .email-header-title { margin:20px 0; font-size:42px; font-weight:700; line-height:1.1; text-shadow: 0 0 20px rgba(255,255,255,0.8), 0 0 40px rgba(255,107,53,0.6), 0 0 60px rgba(193,18,31,0.4); font-family:'Cinzel', serif; letter-spacing:0.1em; position:relative; z-index:1; animation: textGlow 2s ease-in-out infinite; }
    @keyframes textGlow { 0%%,100%% { text-shadow: 0 0 20px rgba(255,255,255,0.8), 0 0 40px rgba(255,107,53,0.6), 0 0 60px rgba(193,18,31,0.4); } 50%% { text-shadow: 0 0 30px rgba(255,255,255,1), 0 0 60px rgba(255,107,53,0.8), 0 0 90px rgba(193,18,31,0.6); } }
    .ring-divider { text-align:center; margin:30px 0; position:relative; }
    .ring-divider::before { content:'⚔'; position:absolute; left:20%%; top:50%%; transform:translateY(-50%%); font-size:24px; color:#d4af37; background:#f4e8d0; padding:0 15px; }
    .ring-divider::after { content:'⚔'; position:absolute; right:20%%; top:50%%; transform:translateY(-50%%); font-size:24px; color:#d4af37; background:#f4e8d0; padding:0 15px; }
    .ring-divider-line { height:3px; background:linear-gradient(90deg, transparent 0%%, #d4af37 20%%, #d4af37 80%%, transparent 100%%); margin:0 25%%; }
    .email-body { padding:36px 28px; background:#f4e8d0; color:#3d2817; }
    .email-intro { font-size:18px; line-height:1.8; margin:0 0 28px; color:#3d2817; font-style:italic; text-align:center; }
    .email-details-wrapper { background:#e8d5b7; border:3px solid #8b7355; border-radius:8px; padding:24px; margin:0 0 32px; box-shadow:inset 0 2px 4px rgba(0,0,0,0.1); }
    .email-details-wrapper p { margin:12px 0; font-size:15px; line-height:1.7; color:#3d2817; }
    .email-details-wrapper p:first-child { margin-top:0; }
    .email-details-wrapper p:last-child { margin-bottom:0; }
    .email-detail-label { font-weight:700; color:#1a4d2e; margin-right:8px; font-family:'Cinzel', serif; }
    .email-section { margin:36px 0 0; }
    .email-section-title { font-size:16px; text-transform:uppercase; letter-spacing:0.2em; color:#1a4d2e; margin:0 0 16px; font-weight:700; font-family:'Cinzel', serif; border-bottom:2px solid #d4af37; padding-bottom:8px; }
    .email-terminal { background:#1a1a1a; color:#d4af37; padding:20px; font-family:"Courier New", Courier, monospace; border-radius:8px; font-size:13px; line-height:1.7; white-space:pre-wrap; word-break:break-word; overflow-x:auto; margin:0; border:2px solid #8b7355; box-shadow:inset 0 0 20px rgba(212,175,55,0.1); }
    .email-log-stack { background:#0f0f0f; border-radius:8px; padding:16px; border:2px solid #8b7355; }
    .email-log-line { font-family:"Courier New", Courier, monospace; font-size:12px; line-height:1.6; color:#d4af37; padding:8px 12px; border-radius:6px; margin:0 0 6px; background:rgba(212,175,55,0.1); border-left:3px solid #d4af37; }
    .email-log-line:last-child { margin-bottom:0; }
    .email-log-line-alert { background:rgba(193,18,31,0.3); color:#ff6b35; border-left-color:#c1121f; }
    .email-muted { color:#8b7355; font-size:14px; line-height:1.6; font-style:italic; }
    .email-footer { border-top:3px solid #d4af37; padding:24px 28px; font-size:13px; color:#3d2817; text-align:center; background:#e8d5b7; font-family:'Cinzel', serif; }
    .email-footer-text { margin:0 0 8px; font-weight:600; }
    .email-footer-copyright { margin:0; font-size:11px; color:#8b7355; }
    .email-header a { color:#ffffff !important; text-decoration:underline; }
    .email-header a:hover { color:#f4e8d0 !important; }
    a { color:#1a4d2e; text-decoration:none; }
    a:hover { color:#2d0a4f; text-decoration:underline; }
    @media only screen and (max-width:600px) {
      .email-wrapper { padding:12px 8px; }
      .email-header { padding:30px 20px; }
      .email-header-title { font-size:32px; }
      .email-body { padding:28px 20px; }
      .email-intro { font-size:16px; }
      .email-details-wrapper { padding:20px; }
      .email-footer { padding:20px 16px; }
    }
    @media only screen and (max-width:480px) {
      .email-header-title { font-size:28px; }
      .email-body { padding:24px 16px; }
      .email-details-wrapper { padding:16px; }
    }
  </style>
</head>
<body>
  <div class="email-wrapper">
    <div class="email-container">
      <div class="email-header">
        <p class="email-header-brand">Middle-earth Security</p>
        <h1 class="email-header-title">YOU SHALL NOT PASS</h1>
        <div class="ring-divider">
          <div class="ring-divider-line"></div>
        </div>
      </div>
      <div class="email-body">
        <p class="email-intro">%s</p>
        <div class="email-details-wrapper">
          %s
        </div>
        <div class="email-section">
          <p class="email-section-title">%s</p>
          %s
        </div>
        <div class="email-section">
          <p class="email-section-title">%s</p>
          %s
        </div>
      </div>
      <div class="email-footer">
        <p class="email-footer-text">%s</p>
        <p class="email-footer-copyright">© %s Swissmakers GmbH. All rights reserved.</p>
      </div>
    </div>
  </div>
</body>
</html>`, html.EscapeString(title), html.EscapeString(intro), detailRows, html.EscapeString(whoisTitle), whoisHTML, html.EscapeString(logsTitle), logsHTML, html.EscapeString(footerText), year)
}

// Renders the default responsive email template.
func buildModernEmailBody(title, intro string, details []emailDetail, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText string) string {
	detailRows := renderEmailDetails(details)
	year := strconv.Itoa(time.Now().Year())
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>%s</title>
  <style>
    * { box-sizing: border-box; }
    body { margin:0; padding:0; background-color:#f6f8fb; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; color:#1f2933; line-height:1.6; -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale; }
    .email-wrapper { width:100%%; padding:20px 10px; }
    .email-container { max-width:640px; margin:0 auto; background:#ffffff; border-radius:20px; box-shadow:0 4px 20px rgba(0,0,0,0.08), 0 0 0 1px rgba(0,0,0,0.04); overflow:hidden; }
    .email-header { background:linear-gradient(135deg,#004cff 0%%,#6c2bd9 100%%); background-color:#004cff; color:#ffffff !important; padding:32px 28px; text-align:center; }
    .email-header-brand { margin:0 0 8px; font-size:11px; letter-spacing:0.3em; text-transform:uppercase; opacity:0.9; font-weight:600; color:#ffffff !important; }
    .email-header-title { margin:0 0 10px; font-size:26px; font-weight:700; line-height:1.2; color:#ffffff !important; }
    .email-header a { color:#ffffff !important; text-decoration:underline; }
    .email-header a:hover { color:#e0e7ff !important; }
    .email-body { padding:36px 28px; }
    a { color:#2563eb; text-decoration:none; }
    a:hover { color:#1d4ed8; text-decoration:underline; }
    .email-intro { font-size:16px; line-height:1.7; margin:0 0 28px; color:#4b5563; }
    .email-details-wrapper { background:#f9fafb; border-radius:12px; padding:20px; margin:0 0 32px; border:1px solid #e5e7eb; }
    .email-details-wrapper p { margin:8px 0; font-size:14px; line-height:1.6; color:#111827; }
    .email-details-wrapper p:first-child { margin-top:0; }
    .email-details-wrapper p:last-child { margin-bottom:0; }
    .email-detail-label { font-weight:700; color:#374151; margin-right:8px; }
    .email-section { margin:36px 0 0; }
    .email-section-title { font-size:13px; text-transform:uppercase; letter-spacing:0.1em; color:#6b7280; margin:0 0 16px; font-weight:700; }
    .email-terminal { background:#111827; color:#f3f4f6; padding:20px; font-family:"SFMono-Regular","Consolas","Liberation Mono","Courier New",monospace; border-radius:12px; font-size:12px; line-height:1.7; white-space:pre-wrap; word-break:break-word; overflow-x:auto; margin:0; }
    .email-log-stack { background:#0f172a; border-radius:12px; padding:16px; }
    .email-log-line { font-family:"SFMono-Regular","Consolas","Liberation Mono","Courier New",monospace; font-size:12px; line-height:1.6; color:#cbd5f5; padding:8px 12px; border-radius:8px; margin:0 0 6px; background:rgba(255,255,255,0.05); }
    .email-log-line:last-child { margin-bottom:0; }
    .email-log-line-alert { background:rgba(248,113,113,0.25); color:#ffffff; border:1px solid rgba(248,113,113,0.5); }
    .email-muted { color:#9ca3af; font-size:13px; line-height:1.6; }
    .email-footer { border-top:1px solid #e5e7eb; padding:24px 28px; font-size:12px; color:#6b7280; text-align:center; background:#fafbfc; }
    .email-footer-text { margin:0 0 8px; }
    .email-footer-copyright { margin:0; font-size:11px; color:#9ca3af; }
    @media only screen and (max-width:600px) {
      .email-wrapper { padding:12px 8px; }
      .email-header { padding:24px 20px; background-color:#004cff !important; }
      .email-header-brand { color:#ffffff !important; }
      .email-header-title { font-size:22px; color:#ffffff !important; }
      .email-body { padding:28px 20px; }
      .email-intro { font-size:15px; }
      .email-details-wrapper { padding:16px; }
      .email-details-wrapper p { font-size:14px; margin:10px 0; }
      .email-footer { padding:20px 16px; }
    }
    @media only screen and (max-width:480px) {
      .email-header { background-color:#004cff !important; }
      .email-header-brand { color:#ffffff !important; }
      .email-header-title { font-size:20px; color:#ffffff !important; }
      .email-body { padding:24px 16px; }
      .email-details-wrapper { padding:12px; }
    }
    @media print {
      .email-header { background:#004cff !important; background-color:#004cff !important; color:#ffffff !important; }
      .email-header-brand { color:#ffffff !important; }
      .email-header-title { color:#ffffff !important; }
      .email-header a { color:#ffffff !important; }
      a { color:#2563eb !important; }
    }
  </style>
</head>
<body>
  <div class="email-wrapper">
    <div class="email-container">
      <div class="email-header">
        <p class="email-header-brand">Fail2Ban UI</p>
        <h1 class="email-header-title">%s</h1>
      </div>
      <div class="email-body">
        <p class="email-intro">%s</p>
        <div class="email-details-wrapper">
          %s
        </div>
        <div class="email-section">
          <p class="email-section-title">%s</p>
          %s
        </div>
        <div class="email-section">
          <p class="email-section-title">%s</p>
          %s
        </div>
      </div>
      <div class="email-footer">
        <p class="email-footer-text">%s</p>
        <p class="email-footer-copyright">© %s Swissmakers GmbH. All rights reserved.</p>
      </div>
    </div>
  </div>
</body>
</html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(intro), detailRows, html.EscapeString(whoisTitle), whoisHTML, html.EscapeString(logsTitle), logsHTML, html.EscapeString(footerText), year)
}

// Builds table rows for the modern/LOTR email templates.
func renderEmailDetails(details []emailDetail) string {
	if len(details) == 0 {
		return `<p class="email-muted">No metadata available.</p>`
	}
	var b strings.Builder
	for _, d := range details {
		b.WriteString(`<p><span class="email-detail-label">`)
		b.WriteString(html.EscapeString(d.Label))
		b.WriteString(`:</span> `)
		b.WriteString(html.EscapeString(d.Value))
		b.WriteString(`</p>`)
		b.WriteString("\n")
	}
	return b.String()
}

// Wraps raw WHOIS text in a styled <pre> block for email.
func formatWhoisForEmail(whois string, lang string, isModern bool) string {
	noDataMsg := getEmailTranslation(lang, "email.whois.no_data")
	if strings.TrimSpace(whois) == "" {
		if isModern {
			return `<p class="email-muted">` + html.EscapeString(noDataMsg) + `</p>`
		}
		return `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(noDataMsg) + `</pre>`
	}
	if isModern {
		return `<pre class="email-terminal">` + html.EscapeString(whois) + `</pre>`
	}
	return `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(whois) + `</pre>`
}

// Highlights suspicious lines and HTTP status codes in email logs.
func formatLogsForEmail(ip, logs string, lang string, isModern bool) string {
	noLogsMsg := getEmailTranslation(lang, "email.logs.no_data")
	if strings.TrimSpace(logs) == "" {
		if isModern {
			return `<p class="email-muted">` + html.EscapeString(noLogsMsg) + `</p>`
		}
		return `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(noLogsMsg) + `</pre>`
	}
	if isModern {
		var b strings.Builder
		b.WriteString(`<div class="email-log-stack">`)
		lines := strings.Split(logs, "\n")
		for _, line := range lines {
			trimmed := strings.TrimRight(line, "\r")
			if trimmed == "" {
				continue
			}
			class := "email-log-line"
			if isSuspiciousLogLineEmail(trimmed, ip) {
				class = "email-log-line email-log-line-alert"
			}
			b.WriteString(`<div class="`)
			b.WriteString(class)
			b.WriteString(`">`)
			b.WriteString(html.EscapeString(trimmed))
			b.WriteString(`</div>`)
		}
		b.WriteString(`</div>`)
		return b.String()
	}
	return `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(logs) + `</pre>`
}

// Checks if the line contains known attack indicators.
func isSuspiciousLogLineEmail(line, ip string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	lowered := strings.ToLower(trimmed)
	containsIP := ip != "" && strings.Contains(trimmed, ip)
	statusCode := extractStatusCodeFromLine(trimmed)
	hasBadStatus := statusCode >= 300
	hasIndicator := false
	for _, indicator := range suspiciousLogIndicators {
		if strings.Contains(lowered, indicator) {
			hasIndicator = true
			break
		}
	}
	if containsIP {
		return hasBadStatus || hasIndicator
	}
	return (hasBadStatus || hasIndicator) && ip == ""
}

// Parses the HTTP status code from a log line.
func extractStatusCodeFromLine(line string) int {
	if match := httpQuotedStatusPattern.FindStringSubmatch(line); len(match) == 2 {
		if code, err := strconv.Atoi(match[1]); err == nil {
			return code
		}
	}
	if match := httpPlainStatusPattern.FindStringSubmatch(line); len(match) == 2 {
		if code, err := strconv.Atoi(match[1]); err == nil {
			return code
		}
	}
	return 0
}

// Composes and sends the ban notification email.
func sendBanAlert(ip, jail, hostname, failures, whois, logs, country string, settings config.AppSettings) error {
	lang := settings.Language
	if lang == "" {
		lang = "en"
	}
	isLOTRMode := config.IsLOTRModeActive(settings.AlertCountries)
	var subject string
	if isLOTRMode {
		subject = fmt.Sprintf("[Middle-earth] %s: %s %s %s",
			getEmailTranslation(lang, "lotr.email.title"),
			ip,
			getEmailTranslation(lang, "email.ban.subject.from"),
			hostname)
	} else {
		subject = fmt.Sprintf("[Fail2Ban] %s: %s %s %s %s", jail,
			getEmailTranslation(lang, "email.ban.subject.banned"),
			ip,
			getEmailTranslation(lang, "email.ban.subject.from"),
			hostname)
	}
	emailStyle := getEmailStyle()
	isModern := emailStyle == "modern"

	var title, intro, whoisTitle, logsTitle, footerText string
	if isLOTRMode {
		title = getEmailTranslation(lang, "lotr.email.title")
		intro = getEmailTranslation(lang, "lotr.email.intro")
		whoisTitle = getEmailTranslation(lang, "email.ban.whois_title")
		logsTitle = getEmailTranslation(lang, "email.ban.logs_title")
		footerText = getEmailTranslation(lang, "lotr.email.footer")
	} else {
		title = getEmailTranslation(lang, "email.ban.title")
		intro = getEmailTranslation(lang, "email.ban.intro")
		whoisTitle = getEmailTranslation(lang, "email.ban.whois_title")
		logsTitle = getEmailTranslation(lang, "email.ban.logs_title")
		footerText = getEmailTranslation(lang, "email.footer.text")
	}
	supportEmail := "support@swissmakers.ch"

	var details []emailDetail
	if isLOTRMode {
		bannedIPLabel := getEmailTranslation(lang, "lotr.email.details.dark_servant_location")
		jailLabel := getEmailTranslation(lang, "lotr.email.details.realm_protection")
		countryLabelKey := getEmailTranslation(lang, "lotr.email.details.origins")
		var countryLabel string
		if country != "" {
			countryLabel = fmt.Sprintf("%s %s", countryLabelKey, country)
		} else {
			countryLabel = fmt.Sprintf("%s Unknown", countryLabelKey)
		}
		timestampLabel := getEmailTranslation(lang, "lotr.email.details.banished_at")

		details = []emailDetail{
			{Label: bannedIPLabel, Value: ip},
			{Label: jailLabel, Value: jail},
			{Label: getEmailTranslation(lang, "email.ban.details.hostname"), Value: hostname},
			{Label: getEmailTranslation(lang, "email.ban.details.failed_attempts"), Value: failures},
			{Label: countryLabel, Value: ""},
			{Label: timestampLabel, Value: time.Now().UTC().Format(time.RFC3339)},
		}
	} else {
		details = []emailDetail{
			{Label: getEmailTranslation(lang, "email.ban.details.banned_ip"), Value: ip},
			{Label: getEmailTranslation(lang, "email.ban.details.jail"), Value: jail},
			{Label: getEmailTranslation(lang, "email.ban.details.hostname"), Value: hostname},
			{Label: getEmailTranslation(lang, "email.ban.details.failed_attempts"), Value: failures},
			{Label: getEmailTranslation(lang, "email.ban.details.country"), Value: country},
			{Label: getEmailTranslation(lang, "email.ban.details.timestamp"), Value: time.Now().UTC().Format(time.RFC3339)},
		}
	}

	whoisHTML := formatWhoisForEmail(whois, lang, isModern)
	logsHTML := formatLogsForEmail(ip, logs, lang, isModern)

	var body string
	if isLOTRMode {
		body = buildLOTREmailBody(title, intro, details, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText)
	} else if isModern {
		body = buildModernEmailBody(title, intro, details, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText)
	} else {
		body = buildClassicEmailBody(title, intro, details, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText, supportEmail)
	}

	return sendEmail(settings.Destemail, subject, body, settings)
}

// Composes and sends the unban notification email.
func sendUnbanAlert(ip, jail, hostname, whois, country string, settings config.AppSettings) error {
	lang := settings.Language
	if lang == "" {
		lang = "en"
	}
	isLOTRMode := config.IsLOTRModeActive(settings.AlertCountries)
	var subject string
	if isLOTRMode {
		subject = fmt.Sprintf("[Middle-earth] %s: %s %s %s",
			getEmailTranslation(lang, "lotr.email.unban.title"),
			ip,
			getEmailTranslation(lang, "email.unban.subject.from"),
			hostname)
	} else {
		subject = fmt.Sprintf("[Fail2Ban] %s: %s %s %s %s", jail,
			getEmailTranslation(lang, "email.unban.subject.unbanned"),
			ip,
			getEmailTranslation(lang, "email.unban.subject.from"),
			hostname)
	}
	emailStyle := getEmailStyle()
	isModern := emailStyle == "modern"

	var title, intro, whoisTitle, footerText string
	if isLOTRMode {
		title = getEmailTranslation(lang, "lotr.email.unban.title")
		intro = getEmailTranslation(lang, "lotr.email.unban.intro")
		whoisTitle = getEmailTranslation(lang, "email.ban.whois_title")
		footerText = getEmailTranslation(lang, "lotr.email.footer")
	} else {
		title = getEmailTranslation(lang, "email.unban.title")
		intro = getEmailTranslation(lang, "email.unban.intro")
		whoisTitle = getEmailTranslation(lang, "email.ban.whois_title")
		footerText = getEmailTranslation(lang, "email.footer.text")
	}
	supportEmail := "support@swissmakers.ch"
	var details []emailDetail
	if isLOTRMode {
		details = []emailDetail{
			{Label: getEmailTranslation(lang, "lotr.email.unban.details.restored_ip"), Value: ip},
			{Label: getEmailTranslation(lang, "email.unban.details.jail"), Value: jail},
			{Label: getEmailTranslation(lang, "email.unban.details.hostname"), Value: hostname},
			{Label: getEmailTranslation(lang, "email.unban.details.country"), Value: country},
			{Label: getEmailTranslation(lang, "email.unban.details.timestamp"), Value: time.Now().UTC().Format(time.RFC3339)},
		}
	} else {
		details = []emailDetail{
			{Label: getEmailTranslation(lang, "email.unban.details.unbanned_ip"), Value: ip},
			{Label: getEmailTranslation(lang, "email.unban.details.jail"), Value: jail},
			{Label: getEmailTranslation(lang, "email.unban.details.hostname"), Value: hostname},
			{Label: getEmailTranslation(lang, "email.unban.details.country"), Value: country},
			{Label: getEmailTranslation(lang, "email.unban.details.timestamp"), Value: time.Now().UTC().Format(time.RFC3339)},
		}
	}

	whoisHTML := formatWhoisForEmail(whois, lang, isModern)

	var body string
	if isLOTRMode {
		body = buildLOTREmailBody(title, intro, details, whoisHTML, "", whoisTitle, "", footerText)
	} else if isModern {
		body = buildModernEmailBody(title, intro, details, whoisHTML, "", whoisTitle, "", footerText)
	} else {
		body = buildClassicEmailBody(title, intro, details, whoisHTML, "", whoisTitle, "", footerText, supportEmail)
	}
	return sendEmail(settings.Destemail, subject, body, settings)
}

// Sends a test email to verify the SMTP configuration.
func TestEmailHandler(c *gin.Context) {
	settings := config.GetSettings()

	lang := settings.Language
	if lang == "" {
		lang = "en"
	}
	testDetails := []emailDetail{
		{Label: getEmailTranslation(lang, "email.test.details.recipient"), Value: settings.Destemail},
		{Label: getEmailTranslation(lang, "email.test.details.smtp_host"), Value: settings.SMTP.Host},
		{Label: getEmailTranslation(lang, "email.test.details.triggered_at"), Value: time.Now().Format(time.RFC1123)},
	}

	title := getEmailTranslation(lang, "email.test.title")
	intro := getEmailTranslation(lang, "email.test.intro")
	whoisTitle := getEmailTranslation(lang, "email.ban.whois_title")
	logsTitle := getEmailTranslation(lang, "email.ban.logs_title")
	footerText := getEmailTranslation(lang, "email.footer.text")
	whoisNoData := getEmailTranslation(lang, "email.test.whois_no_data")
	supportEmail := "support@swissmakers.ch"
	emailStyle := getEmailStyle()
	isModern := emailStyle == "modern"

	whoisHTML := `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(whoisNoData) + `</pre>`
	if isModern {
		whoisHTML = `<p class="email-muted">` + html.EscapeString(whoisNoData) + `</p>`
	}

	sampleLogs := getEmailTranslation(lang, "email.test.sample_logs")
	logsHTML := formatLogsForEmail("", sampleLogs, lang, isModern)

	var testBody string
	if isModern {
		testBody = buildModernEmailBody(title, intro, testDetails, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText)
	} else {
		testBody = buildClassicEmailBody(title, intro, testDetails, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText, supportEmail)
	}

	subject := getEmailTranslation(lang, "email.test.subject")

	err := sendEmail(
		settings.Destemail,
		subject,
		testBody,
		settings,
	)
	if err != nil {
		log.Printf("ERROR: Test email failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send test email: " + err.Error()})
		return
	}
	log.Println("Test email sent successfully!")
	c.JSON(http.StatusOK, gin.H{"message": "Test email sent successfully!"})
}

// Returns the SMTP auth mechanism based on authMethod ("auto", "login", "plain", "cram-md5").
func getSMTPAuth(username, password, authMethod, host string) (smtp.Auth, error) {
	authMethod = strings.ToLower(strings.TrimSpace(authMethod))
	if authMethod == "none" {
		return nil, nil
	}
	if username == "" || password == "" {
		return nil, nil
	}
	if authMethod == "" || authMethod == "auto" {
		// Auto-detect: prefers LOGIN for Office365/Gmail, falls back to PLAIN (default)
		authMethod = "login"
	}
	switch authMethod {
	case "login":
		return LoginAuth(username, password), nil
	case "plain":
		return smtp.PlainAuth("", username, password, host), nil
	case "cram-md5":
		return smtp.CRAMMD5Auth(username, password), nil
	default:
		return nil, fmt.Errorf("unsupported auth method: %s (supported: none, login, plain, cram-md5)", authMethod)
	}
}

// Implements the LOGIN authentication mechanism used by Office365, Gmail, and other providers that require LOGIN instead of PLAIN
type loginAuth struct {
	username, password string
}

func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// No initial response; let the server challenge with "Username:" first.
	// Some SMTP servers reject the non-standard initial-response variant of LOGIN.
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, errors.New("unexpected server challenge")
		}
	}
	return nil, nil
}
