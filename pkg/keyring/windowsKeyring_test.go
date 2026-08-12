package keyring

import (
	"errors"
	"testing"

	"github.com/XeroAPI/xoauth/pkg/oidc"
	platformkeyring "github.com/zalando/go-keyring"
)

func withFakeWindowsKeyring(t *testing.T, values map[string]string) {
	t.Helper()
	originalSet, originalGet, originalDelete := windowsKeyringSet, windowsKeyringGet, windowsKeyringDelete
	windowsKeyringSet = func(service, item, value string) error {
		values[item] = value
		return nil
	}
	windowsKeyringGet = func(service, item string) (string, error) {
		value, ok := values[item]
		if !ok {
			return "", platformkeyring.ErrNotFound
		}
		return value, nil
	}
	windowsKeyringDelete = func(service, item string) error {
		if _, ok := values[item]; !ok {
			return platformkeyring.ErrNotFound
		}
		delete(values, item)
		return nil
	}
	t.Cleanup(func() {
		windowsKeyringSet, windowsKeyringGet, windowsKeyringDelete = originalSet, originalGet, originalDelete
	})
}

func TestWindowsGetTokensAllowsMissingOptionalTokens(t *testing.T) {
	values := map[string]string{
		"client.access": "access-token",
		"client.expiry": "1700000000",
	}
	withFakeWindowsKeyring(t, values)

	result, err := (WindowsKeyRingService{}).GetTokens("client")
	if err != nil {
		t.Fatalf("GetTokens() error = %v", err)
	}
	if result.AccessToken != "access-token" || result.ExpiresAt != 1700000000 {
		t.Fatalf("GetTokens() = %#v, want access token and expiry", result)
	}
	if result.IdentityToken != "" || result.RefreshToken != "" {
		t.Fatalf("GetTokens() optional tokens = %#v, want empty", result)
	}
}

func TestWindowsGetTokensPropagatesOptionalReadFailure(t *testing.T) {
	withFakeWindowsKeyring(t, map[string]string{})
	wantErr := errors.New("credential store unavailable")
	windowsKeyringGet = func(service, item string) (string, error) { return "", wantErr }

	_, err := (WindowsKeyRingService{}).GetTokens("client")
	if err != wantErr {
		t.Fatalf("GetTokens() error = %v, want %v", err, wantErr)
	}
}

func TestWindowsSetTokensReturnsExpiryWriteFailure(t *testing.T) {
	withFakeWindowsKeyring(t, map[string]string{})
	wantErr := errors.New("expiry write failed")
	windowsKeyringSet = func(service, item, value string) error {
		if item == "client.expiry" {
			return wantErr
		}
		return nil
	}

	err := (WindowsKeyRingService{}).SetTokens("client", oidc.TokenResultSet{
		AccessToken: "access-token",
		ExpiresAt:   1700000000,
	})
	if err != wantErr {
		t.Fatalf("SetTokens() error = %v, want %v", err, wantErr)
	}
}

func TestWindowsDeleteTokensAttemptsEveryCredential(t *testing.T) {
	withFakeWindowsKeyring(t, map[string]string{
		"client.identity": "identity-token",
		"client.access":   "access-token",
	})

	if err := (WindowsKeyRingService{}).DeleteTokens("client"); err != nil {
		t.Fatalf("DeleteTokens() error = %v", err)
	}
}
