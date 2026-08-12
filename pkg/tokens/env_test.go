package tokens

import (
	"strings"
	"testing"

	"github.com/XeroAPI/xoauth/pkg/oidc"
)

func TestFormatEnvVarsQuotesValuesForPOSIXShell(t *testing.T) {
	got := FormatEnvVars("client-name;rm", oidc.TokenResultSet{
		AccessToken:   "$(touch /tmp/pwned)",
		IdentityToken: "identity token",
		RefreshToken:  "refresh'token",
	})

	want := strings.Join([]string{
		"export CLIENT_NAME_RM_ACCESS_TOKEN='$(touch /tmp/pwned)'",
		"export CLIENT_NAME_RM_ID_TOKEN='identity token'",
		"export CLIENT_NAME_RM_REFRESH_TOKEN='refresh'\"'\"'token'",
	}, "\n")
	if got != want {
		t.Fatalf("FormatEnvVars() = %q, want %q", got, want)
	}
}

func TestNormaliseEnvNameProducesValidLeadingCharacter(t *testing.T) {
	if got := normaliseEnvName("123 client"); got != "_123_CLIENT" {
		t.Fatalf("normaliseEnvName() = %q, want %q", got, "_123_CLIENT")
	}
	if got := normaliseEnvName(""); got != "XOAUTH" {
		t.Fatalf("normaliseEnvName(empty) = %q, want XOAUTH", got)
	}
}
