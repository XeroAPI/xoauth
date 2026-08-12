package tokens

import (
	"strings"
	"testing"
	"time"

	"github.com/XeroAPI/xoauth/pkg/oidc"
)

func TestApplyRefreshResultPreservesRotatingTokenWhenOmitted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	original := oidc.TokenResultSet{
		IdentityToken: "identity-token",
		RefreshToken:  "existing-refresh-token",
	}

	got := applyRefreshResult(original, oidc.RefreshResult{
		AccessToken: "new-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   1800,
	}, now)

	if got.RefreshToken != original.RefreshToken {
		t.Fatalf("refresh token = %q, want preserved token %q", got.RefreshToken, original.RefreshToken)
	}
	if got.IdentityToken != original.IdentityToken {
		t.Fatalf("identity token = %q, want preserved token %q", got.IdentityToken, original.IdentityToken)
	}
	if got.AccessToken != "new-access-token" || got.TokenType != "Bearer" {
		t.Fatalf("updated token set = %#v", got)
	}
}

func TestApplyRefreshResultUsesRotatedRefreshToken(t *testing.T) {
	got := applyRefreshResult(oidc.TokenResultSet{RefreshToken: "old"}, oidc.RefreshResult{
		RefreshToken: "rotated",
		AccessToken:  "access",
		ExpiresIn:    1800,
	}, time.Unix(1_700_000_000, 0))

	if got.RefreshToken != "rotated" {
		t.Fatalf("refresh token = %q, want rotated", got.RefreshToken)
	}
}

func TestRefreshReturnsMissingRefreshTokenError(t *testing.T) {
	_, err := Refresh(nil, "client", oidc.TokenResultSet{})
	if err == nil || !strings.Contains(err.Error(), "no refresh token") {
		t.Fatalf("Refresh() error = %v, want missing-token error", err)
	}
}
