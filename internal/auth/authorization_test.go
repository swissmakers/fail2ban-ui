package auth

import (
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

func TestAccessLevelForRoles(t *testing.T) {
	cfg := &config.OIDCConfig{
		AuthorizationEnabled: true,
		AdminRoles:           []string{"fail2ban-admins"},
		SupportRoles:         []string{"fail2ban-support"},
	}

	if got := accessLevelForRoles(cfg, []string{"fail2ban-admins"}); got != AccessLevelAdmin {
		t.Fatalf("admin role access level = %q, want %q", got, AccessLevelAdmin)
	}
	if got := accessLevelForRoles(cfg, []string{"fail2ban-support"}); got != AccessLevelSupport {
		t.Fatalf("support role access level = %q, want %q", got, AccessLevelSupport)
	}
	if got := accessLevelForRoles(cfg, []string{"other"}); got != "" {
		t.Fatalf("unknown role access level = %q, want empty", got)
	}
}

func TestSessionHasPermission(t *testing.T) {
	admin := &Session{AccessLevel: AccessLevelAdmin}
	if !SessionHasPermission(admin, "admin") || !SessionHasPermission(admin, "ban") {
		t.Fatal("admin should have all permissions")
	}

	support := &Session{AccessLevel: AccessLevelSupport}
	if !SessionHasPermission(support, "read") || !SessionHasPermission(support, "ban") {
		t.Fatal("support should have read and ban permissions")
	}
	if SessionHasPermission(support, "admin") {
		t.Fatal("support should not have admin permission")
	}
}

func TestClaimByPathAndStringSliceFromClaim(t *testing.T) {
	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"fail2ban-admins", "offline_access"},
		},
	}

	roles := stringSliceFromClaim(claimByPath(claims, "realm_access.roles"))
	if len(roles) != 2 || roles[0] != "fail2ban-admins" || roles[1] != "offline_access" {
		t.Fatalf("roles = %#v, want nested role slice", roles)
	}
}
