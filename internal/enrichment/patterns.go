// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package enrichment

// =========================================================================
//  Types / Variables
// =========================================================================

// Describes a single log format pattern.
type PatternDef struct {
	Name     string
	Pattern  string
	Category string
	Action   string
	Process  string
}

// Custom grok sub-patterns registered alongside the built-in defaults from elastic/go-grok.
// They are referenced by the top-level log format patterns below.
var SubPatterns = map[string]string{
	"F2B_HTTPDUSER":       `[a-zA-Z0-9._@%+-]+`,
	"F2B_NGINX_TS":        `\d{4}/\d{2}/\d{2} %{TIME}`,
	"F2B_APACHE_ERROR_TS": `%{DAY} %{MONTH} %{MONTHDAY} %{TIME}(?:\.\d+)? %{YEAR}`,
	"F2B_SYSLOG_PREFIX":   `%{SYSLOGTIMESTAMP:log.timestamp} %{SYSLOGHOST:log.syslog.hostname} %{PROG:process.name}(?:\[%{POSINT:process.pid:int}\])?:`,
}

// =========================================================================
//  HTTP Access / Error Log Patterns (highest priority first)
// =========================================================================

var HTTPPatterns = []PatternDef{
	{
		// Apache/Nginx combined log format with vhost/server-name prefix
		// www.example.ch 1.1.1.1 - - [23/Feb/2026:14:37:29 +0100] "GET /.git/config HTTP/1.1" 301 248 "-" "Mozilla/5.0"
		Name:     "http_combined_vhost",
		Category: "http",
		Action:   "http_request",
		Process:  "httpd",
		Pattern:  `%{IPORHOST:server.address} %{IPORHOST:source.address} (?:-|%{F2B_HTTPDUSER}) (?:-|%{F2B_HTTPDUSER:source.user.name}) \[%{HTTPDATE:log.timestamp}\] "(?:%{WORD:http.request.method} %{NOTSPACE:url.original}(?: HTTP/%{NUMBER:http.version})?|%{DATA})" (?:-|%{INT:http.response.status_code:int}) (?:-|%{INT:http.response.body.bytes:int}) "(?:-|%{DATA:http.request.referrer})" "(?:-|%{DATA:user_agent.original})"`,
	},
	{
		// Apache/Nginx combined log format
		// 1.1.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/" "Mozilla/4.08"
		Name:     "http_combined",
		Category: "http",
		Action:   "http_request",
		Process:  "httpd",
		Pattern:  `%{IPORHOST:source.address} (?:-|%{F2B_HTTPDUSER}) (?:-|%{F2B_HTTPDUSER:source.user.name}) \[%{HTTPDATE:log.timestamp}\] "(?:%{WORD:http.request.method} %{NOTSPACE:url.original}(?: HTTP/%{NUMBER:http.version})?|%{DATA})" (?:-|%{INT:http.response.status_code:int}) (?:-|%{INT:http.response.body.bytes:int}) "(?:-|%{DATA:http.request.referrer})" "(?:-|%{DATA:user_agent.original})"`,
	},
	{
		// Apache/Nginx common log format
		// 1.1.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /page HTTP/1.0" 200 2326
		Name:     "http_common",
		Category: "http",
		Action:   "http_request",
		Process:  "httpd",
		Pattern:  `%{IPORHOST:source.address} (?:-|%{F2B_HTTPDUSER}) (?:-|%{F2B_HTTPDUSER:source.user.name}) \[%{HTTPDATE:log.timestamp}\] "(?:%{WORD:http.request.method} %{NOTSPACE:url.original}(?: HTTP/%{NUMBER:http.version})?|%{DATA})" (?:-|%{INT:http.response.status_code:int}) (?:-|%{INT:http.response.body.bytes:int})`,
	},
	{
		// Apache 2.4 error log format (with module, PID, optional TID)
		// [Thu Feb 23 14:37:29.123456 2026] [core:error] [pid 12345:tid 678] [client 1.1.1.1:54321] AH00126: error message
		Name:     "apache_error_24",
		Category: "http",
		Action:   "http_error",
		Process:  "apache",
		Pattern:  `\[%{F2B_APACHE_ERROR_TS:log.timestamp}\] \[(?:%{WORD:apache.module}:)?%{LOGLEVEL:log.level}\] \[pid %{POSINT:process.pid:int}(?::tid %{INT})?\]%{DATA}\[client %{IP:source.address}(?::%{POSINT:source.port:int})?\] %{GREEDYDATA:message}`,
	},
	{
		// Apache 2.0 error log format (no PID block)
		// [Thu Feb 23 14:37:29 2026] [error] [client 1.1.1.1] error message
		Name:     "apache_error_20",
		Category: "http",
		Action:   "http_error",
		Process:  "apache",
		Pattern:  `\[%{F2B_APACHE_ERROR_TS:log.timestamp}\] \[%{LOGLEVEL:log.level}\]%{DATA}\[client %{IP:source.address}(?::%{POSINT:source.port:int})?\] %{GREEDYDATA:message}`,
	},
	{
		// Nginx error log format
		// 2026/02/23 14:37:29 [error] 1234#0: *5678 access forbidden, client: 1.1.1.1, server: example.com, request: "GET /.git/config HTTP/1.1"
		Name:     "nginx_error",
		Category: "http",
		Action:   "http_error",
		Process:  "nginx",
		Pattern:  `%{F2B_NGINX_TS:log.timestamp} \[%{LOGLEVEL:log.level}\] %{POSINT:process.pid:int}#%{NONNEGINT}: \*%{NONNEGINT} %{DATA:message}, client: %{IP:source.address}(?:, server: %{NOTSPACE:server.address})?(?:, request: "(?:%{WORD:http.request.method} %{NOTSPACE:url.original}(?: HTTP/%{NUMBER:http.version})?)?")?%{GREEDYDATA}`,
	},
}

// =========================================================================
//  SSH Authentication Patterns
// =========================================================================

var SSHPatterns = []PatternDef{
	{
		// sshd failed password
		// Feb 23 14:37:29 myhost sshd[12345]: Failed password for root from 1.1.1.1 port 54321 ssh2
		// Feb 23 14:37:29 myhost sshd[12345]: Failed password for invalid user admin from 1.1.1.1 port 54321 ssh2
		Name:     "sshd_failed_password",
		Category: "ssh",
		Action:   "failed_password",
		Process:  "sshd",
		Pattern:  `%{F2B_SYSLOG_PREFIX} [Ff]ailed password for (?:invalid user )?%{USERNAME:source.user.name} from %{IP:source.address} port %{INT:source.port:int}%{GREEDYDATA}`,
	},
	{
		// sshd invalid user
		// Feb 23 14:37:29 myhost sshd[12345]: Invalid user admin from 1.1.1.1 port 54321
		Name:     "sshd_invalid_user",
		Category: "ssh",
		Action:   "invalid_user",
		Process:  "sshd",
		Pattern:  `%{F2B_SYSLOG_PREFIX} [Ii]nvalid user %{USERNAME:source.user.name} from %{IP:source.address} port %{INT:source.port:int}%{GREEDYDATA}`,
	},
	{
		// sshd disconnect / connection closed (preauth)
		// Feb 23 14:37:29 myhost sshd[12345]: Disconnected from authenticating user root 1.1.1.1 port 54321 [preauth]
		// Feb 23 14:37:29 myhost sshd[12345]: Connection closed by authenticating user root 1.1.1.1 port 54321 [preauth]
		Name:     "sshd_disconnect",
		Category: "ssh",
		Action:   "disconnect",
		Process:  "sshd",
		Pattern:  `%{F2B_SYSLOG_PREFIX} (?:[Dd]isconnected from|[Cc]onnection closed by)(?: (?:authenticating|invalid))? user %{USERNAME:source.user.name} %{IP:source.address} port %{INT:source.port:int}%{GREEDYDATA}`,
	},
	{
		// PAM authentication failure
		// Feb 23 14:37:29 myhost sshd[12345]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.1.1.1
		// Feb 23 14:37:29 myhost sshd[12345]: pam_unix(sshd:auth): authentication failure; ... rhost=1.1.1.1 user=root
		Name:     "sshd_pam_failure",
		Category: "ssh",
		Action:   "pam_auth_failure",
		Process:  "sshd",
		Pattern:  `%{F2B_SYSLOG_PREFIX} pam_unix\(%{DATA}\): authentication failure;%{DATA}rhost=%{IP:source.address}(?:%{DATA}user=%{USERNAME:source.user.name})?%{GREEDYDATA}`,
	},
}

// =========================================================================
//  Mail Server Patterns
// =========================================================================

var MailPatterns = []PatternDef{
	{
		// Postfix reject
		// Feb 23 14:37:29 myhost postfix/smtpd[12345]: NOQUEUE: reject: RCPT from unknown[1.1.1.1]: 554 5.7.1 Relay access denied
		Name:     "postfix_reject",
		Category: "mail",
		Action:   "mail_reject",
		Process:  "postfix",
		Pattern:  `%{F2B_SYSLOG_PREFIX} NOQUEUE: reject: %{WORD:postfix.action} from %{DATA}\[%{IP:source.address}\]:%{GREEDYDATA:message}`,
	},
	{
		// Postfix auth failure
		// Feb 23 14:37:29 myhost postfix/smtpd[12345]: warning: unknown[1.1.1.1]: SASL LOGIN authentication failed: ...
		Name:     "postfix_auth",
		Category: "mail",
		Action:   "mail_auth_failure",
		Process:  "postfix",
		Pattern:  `%{F2B_SYSLOG_PREFIX} warning: %{DATA}\[%{IP:source.address}\]: SASL %{WORD} authentication failed%{GREEDYDATA:message}`,
	},
	{
		// Dovecot auth failure
		// Feb 23 14:37:29 myhost dovecot: imap-login: Disconnected (auth failed, 3 attempts): user=<testuser>, method=PLAIN, rip=1.1.1.1, lip=192.168.1.1
		Name:     "dovecot_auth",
		Category: "mail",
		Action:   "auth_failure",
		Process:  "dovecot",
		Pattern:  `%{F2B_SYSLOG_PREFIX} %{DATA}: %{DATA:message}: user=<?%{DATA:source.user.name}>?,%{DATA}rip=%{IP:source.address}%{GREEDYDATA}`,
	},
}

// =========================================================================
//  Fallback Patterns (if no other pattern matches)
// =========================================================================

var FallbackPatterns = []PatternDef{
	{
		// Generic syslog line
		Name:     "generic_syslog",
		Category: "syslog",
		Action:   "syslog_event",
		Pattern:  `%{F2B_SYSLOG_PREFIX} %{GREEDYDATA:message}`,
	},
}
