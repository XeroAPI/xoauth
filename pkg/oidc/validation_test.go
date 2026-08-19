package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
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
		expiry          interface{}
		omitExpiry      bool
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
			name:       "rejects empty audience list",
			audience:   []string{},
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
		{
			name:       "rejects expired token",
			audience:   clientID,
			issuer:     issuer,
			signingKey: trustedKey,
			expiry:     time.Now().Add(-2 * time.Hour).Unix(),
			wantErr:    true,
		},
		{
			name:       "rejects token without an expiry",
			audience:   clientID,
			issuer:     issuer,
			signingKey: trustedKey,
			omitExpiry: true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := signedIDToken(t, idTokenParams{
				signingKey:      tt.signingKey,
				issuer:          tt.issuer,
				audience:        tt.audience,
				authorizedParty: tt.authorizedParty,
				expiry:          tt.expiry,
				omitExpiry:      tt.omitExpiry,
			})

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

// TestValidateIDTokenRejectsSymmetricallySignedToken covers the algorithm
// confusion vector that getKeyValidatorFunc exists to block: the token header
// claims HMAC so that a published RSA verification key would be handed to a
// symmetric signing method. The shared secret is irrelevant because the token
// has to be refused before any key is looked up.
func TestValidateIDTokenRejectsSymmetricallySignedToken(t *testing.T) {
	trustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate trusted RSA key: %v", err)
	}

	configuration, closeJWKS := testWellKnownConfiguration(t, &trustedKey.PublicKey)
	defer closeJWKS()

	const clientID = "expected-client"

	tokenString := signedIDToken(t, idTokenParams{
		signingMethod: jwt.SigningMethodHS256,
		signingKey:    []byte("attacker-chosen-shared-secret"),
		issuer:        "https://issuer.example",
		audience:      clientID,
	})

	claims, err := ValidateIDToken(tokenString, configuration, clientID)
	if err == nil {
		t.Fatal("ValidateIDToken() error = nil, want an HMAC signed token to be rejected")
	}
	if claims != nil {
		t.Fatalf("ValidateIDToken() claims = %v, want nil", claims)
	}

	// The key function has to refuse the token, which the parser reports as an
	// unverifiable token. Dropping the *jwt.SigningMethodRSA assertion would
	// hand the RSA public key to the HMAC verifier instead, producing an
	// invalid signature error, so this assertion guards that check.
	var unverifiable *jwt.UnverfiableTokenError
	if !errors.As(err, &unverifiable) {
		t.Fatalf("ValidateIDToken() error = %v (%T), want *jwt.UnverfiableTokenError", err, err)
	}
}

func TestValidateTokenDoesNotRequireClientIDAudienceForAccessTokens(t *testing.T) {
	trustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate trusted RSA key: %v", err)
	}

	configuration, closeJWKS := testWellKnownConfiguration(t, &trustedKey.PublicKey)
	defer closeJWKS()

	accessToken := signedIDToken(t, idTokenParams{
		signingKey: trustedKey,
		issuer:     "https://issuer.example",
		audience:   "https://identity.xero.com/resources",
	})

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

// idTokenParams describes the token signedIDToken should mint. A nil
// signingMethod defaults to RS256 and a nil expiry defaults to one hour in the
// future; omitExpiry drops the exp claim entirely.
type idTokenParams struct {
	signingMethod   jwt.SigningMethod
	signingKey      interface{}
	issuer          string
	audience        interface{}
	authorizedParty interface{}
	expiry          interface{}
	omitExpiry      bool
}

func signedIDToken(t *testing.T, params idTokenParams) string {
	t.Helper()

	signingMethod := params.signingMethod
	if signingMethod == nil {
		signingMethod = jwt.SigningMethodRS256
	}

	claims := jwt.MapClaims{
		"iss": params.issuer,
	}
	if !params.omitExpiry {
		expiry := params.expiry
		if expiry == nil {
			expiry = time.Now().Add(time.Hour).Unix()
		}
		claims["exp"] = expiry
	}
	if params.audience != nil {
		claims["aud"] = params.audience
	}
	if params.authorizedParty != nil {
		claims["azp"] = params.authorizedParty
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = testKeyID

	signed, err := token.SignedString(params.signingKey)
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}
	return signed
}
