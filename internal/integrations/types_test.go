package integrations

import "testing"

func TestValidateOutboundURL(t *testing.T) {
	t.Parallel()

	valid := []string{
		"http://192.168.1.1",
		"https://firewall.local",
		"http://10.0.0.5:8443/api",
		"https://example.com/path?q=1",
	}
	for _, raw := range valid {
		if err := ValidateOutboundURL(raw, "test URL"); err != nil {
			t.Fatalf("ValidateOutboundURL(%q): unexpected error %v", raw, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"ftp://example.com",
		"file:///etc/passwd",
		"gopher://example.com",
		"javascript:alert(1)",
		"http://",
		"://example.com",
		"http://exa\r\nmple.com",
	}
	for _, raw := range invalid {
		if err := ValidateOutboundURL(raw, "test URL"); err == nil {
			t.Fatalf("ValidateOutboundURL(%q): expected error, got nil", raw)
		}
	}
}
