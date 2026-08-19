package tokens

import (
	"strings"
	"testing"
	"time"

	"github.com/XeroAPI/xoauth/pkg/db"
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

type fakeRefreshStore struct {
	clients   map[string]db.OidcClient
	client    db.OidcClient
	saved     oidc.TokenResultSet
	saveCalls int
}

func (store *fakeRefreshStore) GetClients() (map[string]db.OidcClient, error) {
	return store.clients, nil
}

func (store *fakeRefreshStore) GetClientWithSecret(allClients map[string]db.OidcClient, name string) (db.OidcClient, error) {
	return store.client, nil
}

func (store *fakeRefreshStore) SaveTokens(clientName string, tokenSet oidc.TokenResultSet) (bool, error) {
	store.saveCalls++
	store.saved = tokenSet
	return true, nil
}

func TestRefreshPersistsTheMergedTokenSet(t *testing.T) {
	store := &fakeRefreshStore{
		clients: map[string]db.OidcClient{"client": {Alias: "client"}},
		client: db.OidcClient{
			Alias:     "client",
			Authority: "https://issuer.example",
			ClientId:  "client-id",
		},
	}

	previousRefresh := refreshToken
	refreshToken = func(authority string, clientId string, clientSecret string, token string) (oidc.RefreshResult, error) {
		if token != "existing-refresh-token" {
			t.Fatalf("refresh called with %q, want the stored refresh token", token)
		}
		// The issuer answers without rotating the refresh token.
		return oidc.RefreshResult{
			AccessToken: "new-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   1800,
		}, nil
	}
	defer func() { refreshToken = previousRefresh }()

	result, err := Refresh(store, "client", oidc.TokenResultSet{
		AccessToken:   "old-access-token",
		IdentityToken: "identity-token",
		RefreshToken:  "existing-refresh-token",
	})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	if store.saveCalls != 1 {
		t.Fatalf("SaveTokens called %d times, want 1", store.saveCalls)
	}
	if store.saved.RefreshToken != "existing-refresh-token" {
		t.Fatalf("persisted refresh token = %q, want the preserved token", store.saved.RefreshToken)
	}
	if store.saved.AccessToken != "new-access-token" {
		t.Fatalf("persisted access token = %q, want the refreshed token", store.saved.AccessToken)
	}
	if store.saved.IdentityToken != "identity-token" {
		t.Fatalf("persisted identity token = %q, want the preserved token", store.saved.IdentityToken)
	}
	if result != store.saved {
		t.Fatalf("Refresh() = %#v, want the persisted set %#v", result, store.saved)
	}
}
