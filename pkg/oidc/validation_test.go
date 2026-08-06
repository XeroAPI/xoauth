package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

const testKeyID = "test-signing-key"

func TestValidateIDTokenValidatesAudienceIssuerAndSignature(t *testing.T) {
	trustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate trusted RSA key: %v", err)
	}

	untrustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate untrusted RSA key: %v", err)
	}

	configuration, closeJWKS := testWellKnownConfiguration(t, &trustedKey.PublicKey)
	defer closeJWKS()

	const clientID = "expected-client"
	const issuer = "https://issuer.example"

	tests := []struct {
		name            string
		audience        interface{}
		authorizedParty interface{}
		issuer          string
		signingKey      *rsa.PrivateKey
		wantErr         bool
	}{
		{
			name:       "accepts matching audience",
			audience:   clientID,
			issuer:     issuer,
			signingKey: trustedKey,
		},
		{
			name:            "accepts multiple audiences with matching authorized party",
			audience:        []string{clientID, "another-client"},
			authorizedParty: clientID,
			issuer:          issuer,
			signingKey:      trustedKey,
		},
		{
			name:       "rejects mismatched audience",
			audience:   "another-client",
			issuer:     issuer,
			signingKey: trustedKey,
			wantErr:    true,
		},
		{
			name:       "rejects missing audience",
			issuer:     issuer,
			signingKey: trustedKey,
			wantErr:    true,
		},
		{
			name:       "rejects multiple audiences without an authorized party",
			audience:   []string{clientID, "another-client"},
			issuer:     issuer,
			signingKey: trustedKey,
			wantErr:    true,
		},
		{
			name:            "rejects mismatched authorized party",
			audience:        []string{clientID, "another-client"},
			authorizedParty: "another-client",
			issuer:          issuer,
			signingKey:      trustedKey,
			wantErr:         true,
		},
		{
			name:       "rejects mismatched issuer",
			audience:   clientID,
			issuer:     "https://different-issuer.example",
			signingKey: trustedKey,
			wantErr:    true,
		},
		{
			name:       "rejects invalid signature",
			audience:   clientID,
			issuer:     issuer,
			signingKey: untrustedKey,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := signedIDToken(t, tt.signingKey, tt.issuer, tt.audience, tt.authorizedParty)

			claims, err := ValidateIDToken(tokenString, configuration, clientID)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ValidateToken() error = nil, want non-nil error")
				}
				return
			}

			if err != nil {
				t.Fatalf("ValidateToken() error = %v", err)
			}

			mapClaims, ok := claims.(jwt.MapClaims)
			if !ok {
				t.Fatalf("ValidateToken() claims type = %T, want jwt.MapClaims", claims)
			}
			if got := mapClaims["aud"]; got == nil {
				t.Fatal("ValidateIDToken() audience = nil, want a client audience")
			}
		})
	}
}

func TestValidateTokenDoesNotRequireClientIDAudienceForAccessTokens(t *testing.T) {
	trustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate trusted RSA key: %v", err)
	}

	configuration, closeJWKS := testWellKnownConfiguration(t, &trustedKey.PublicKey)
	defer closeJWKS()

	accessToken := signedIDToken(
		t,
		trustedKey,
		"https://issuer.example",
		"https://identity.xero.com/resources",
		nil,
	)

	if _, err := ValidateToken(accessToken, configuration, "expected-client"); err != nil {
		t.Fatalf("ValidateToken() error = %v, want nil for a valid access token", err)
	}
}

func testWellKnownConfiguration(t *testing.T, publicKey *rsa.PublicKey) (WellKnownConfiguration, func()) {
	t.Helper()

	key, err := jwk.New(publicKey)
	if err != nil {
		t.Fatalf("create JWK: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, testKeyID); err != nil {
		t.Fatalf("set JWK key ID: %v", err)
	}

	encodedSet, err := json.Marshal(jwk.Set{Keys: []jwk.Key{key}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(encodedSet); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))

	return WellKnownConfiguration{
		Issuer:  "https://issuer.example",
		JwksUri: server.URL,
	}, server.Close
}

func signedIDToken(t *testing.T, signingKey *rsa.PrivateKey, issuer string, audience interface{}, authorizedParty interface{}) string {
	t.Helper()

	claims := jwt.MapClaims{
		"iss": issuer,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	if audience != nil {
		claims["aud"] = audience
	}
	if authorizedParty != nil {
		claims["azp"] = authorizedParty
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKeyID

	signed, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}
	return signed
}
