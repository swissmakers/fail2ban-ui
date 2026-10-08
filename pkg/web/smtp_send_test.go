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
	"net"
	"net/smtp"
	"net/textproto"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// Scripted SMTP peer; rcptCode and dataCode are the replies to RCPT and to the end of DATA.
func fakeSMTPServer(t *testing.T, conn net.Conn, rcptCode, dataCode string) {
	t.Helper()
	tp := textproto.NewConn(conn)
	defer tp.Close()
	reply := func(line string) { _ = tp.PrintfLine("%s", line) }
	reply("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		switch cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0]); cmd {
		case "EHLO", "HELO":
			reply("250 fake")
		case "MAIL":
			reply("250 ok")
		case "RCPT":
			reply(rcptCode)
		case "DATA":
			reply("354 go ahead")
			if _, err := tp.ReadDotLines(); err != nil {
				return
			}
			reply(dataCode)
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 unknown")
		}
	}
}

func TestSendSMTPMessage(t *testing.T) {
	tests := []struct {
		name     string
		rcptCode string
		dataCode string
		wantErr  string
	}{
		{name: "accepted", rcptCode: "250 ok", dataCode: "250 queued"},
		{name: "rejected after data", rcptCode: "250 ok", dataCode: "554 spam detected", wantErr: "server rejected message"},
		{name: "recipient refused", rcptCode: "550 no such user", dataCode: "250 queued", wantErr: "failed to set recipient"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				fakeSMTPServer(t, serverConn, tt.rcptCode, tt.dataCode)
			}()
			client, err := smtp.NewClient(clientConn, "fake")
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			err = sendSMTPMessage(client, "from@example.com", []string{"to@example.com"}, []byte("Subject: x\r\n\r\nbody\r\n"))
			_ = client.Quit()
			_ = client.Close()
			<-done
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestSendSMTPMessageKeepsDotAndCommandsInsideBody(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = serverConn.SetDeadline(time.Now().Add(5 * time.Second))
	type receivedMail struct {
		commands []string
		lines    []string
		err      error
	}
	received := make(chan receivedMail, 1)
	go func() {
		var got receivedMail
		defer func() { received <- got }()
		peer := textproto.NewConn(serverConn)
		defer peer.Close()
		_ = peer.PrintfLine("220 fake ESMTP")
		for {
			line, err := peer.ReadLine()
			if err != nil {
				got.err = err
				return
			}
			command := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
			got.commands = append(got.commands, command)
			switch command {
			case "DATA":
				_ = peer.PrintfLine("354 go ahead")
				got.lines, got.err = peer.ReadDotLines()
				if got.err != nil {
					return
				}
				_ = peer.PrintfLine("250 queued")
			case "QUIT":
				_ = peer.PrintfLine("221 bye")
				return
			default:
				_ = peer.PrintfLine("250 ok")
			}
		}
	}()
	client, err := smtp.NewClient(clientConn, "fake")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// A standalone dot in untrusted text must not end DATA and inject SMTP commands.
	wantLines := []string{"Subject: alert", "", "body", ".", "MAIL FROM:<attacker@example.com>", "RCPT TO:<victim@example.com>", "DATA", "spoofed message", "."}
	message := strings.Join(wantLines, "\r\n") + "\r\n"
	if err := sendSMTPMessage(client, "from@example.com", []string{"to@example.com"}, []byte(message)); err != nil {
		t.Fatal(err)
	}
	if err := client.Quit(); err != nil {
		t.Fatal(err)
	}
	got := <-received
	if got.err != nil {
		t.Fatal(got.err)
	}
	if !reflect.DeepEqual(got.lines, wantLines) {
		t.Fatalf("message body changed or ended early: got %q, want %q", got.lines, wantLines)
	}
	if want := []string{"EHLO", "MAIL", "RCPT", "DATA", "QUIT"}; !reflect.DeepEqual(got.commands, want) {
		t.Fatalf("unexpected SMTP commands: got %q, want %q", got.commands, want)
	}
}

func TestSMTPPlaintextAuth(t *testing.T) {
	base := config.SMTPSettings{Host: "mail.example.com", Port: 25, Username: "u", Password: "p", AuthMethod: "login"}
	tests := []struct {
		name string
		mod  func(*config.SMTPSettings)
		want bool
	}{
		{name: "remote plaintext", mod: func(*config.SMTPSettings) {}, want: true},
		{name: "starttls", mod: func(s *config.SMTPSettings) { s.UseTLS = true }, want: false},
		{name: "implicit tls", mod: func(s *config.SMTPSettings) { s.Port = 465 }, want: false},
		{name: "auth none", mod: func(s *config.SMTPSettings) { s.AuthMethod = "none" }, want: false},
		{name: "cram-md5", mod: func(s *config.SMTPSettings) { s.AuthMethod = "cram-md5" }, want: false},
		{name: "auto means login", mod: func(s *config.SMTPSettings) { s.AuthMethod = "auto" }, want: true},
		{name: "no credentials", mod: func(s *config.SMTPSettings) { s.Password = "" }, want: false},
		{name: "localhost", mod: func(s *config.SMTPSettings) { s.Host = "localhost" }, want: false},
		{name: "loopback ip", mod: func(s *config.SMTPSettings) { s.Host = "127.0.0.1" }, want: false},
		{name: "ipv6 loopback", mod: func(s *config.SMTPSettings) { s.Host = "::1" }, want: false},
		{name: "remote ip", mod: func(s *config.SMTPSettings) { s.Host = "192.0.2.10" }, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := base
			tt.mod(&s)
			if got := smtpPlaintextAuth(s); got != tt.want {
				t.Fatalf("smtpPlaintextAuth = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEmailConfigured(t *testing.T) {
	ok := config.AppSettings{Destemail: "a@example.com", SMTP: config.SMTPSettings{Host: "mail", From: "f@example.com"}}
	tests := []struct {
		name string
		mod  func(*config.AppSettings)
		want bool
	}{
		{name: "complete", mod: func(*config.AppSettings) {}, want: true},
		{name: "no destination", mod: func(s *config.AppSettings) { s.Destemail = " " }, want: false},
		{name: "no host", mod: func(s *config.AppSettings) { s.SMTP.Host = "" }, want: false},
		{name: "no sender", mod: func(s *config.AppSettings) { s.SMTP.From = "" }, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ok
			tt.mod(&s)
			if got := emailConfigured(s); got != tt.want {
				t.Fatalf("emailConfigured = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRenderDetailRows(t *testing.T) {
	got := renderDetailRows([]emailDetail{{Label: "IP", Value: "<b>1.2.3.4</b>"}}, "label", "EMPTY")
	if got != "<p><span class=\"label\">IP:</span> &lt;b&gt;1.2.3.4&lt;/b&gt;</p>\n" {
		t.Fatalf("unexpected row: %q", got)
	}
	if renderDetailRows(nil, "label", "EMPTY") != "EMPTY" {
		t.Fatal("empty details must render the placeholder")
	}
	if classicPre("<x>") != strings.Replace(classicPre("X"), "X", "&lt;x&gt;", 1) {
		t.Fatal("classicPre must escape its text")
	}
}
