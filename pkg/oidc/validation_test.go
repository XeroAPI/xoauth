package oidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateTokenRejectsOversizedJWKS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", maxOIDCResponseBytes+1))
	}))
	defer server.Close()

	configuration := WellKnownConfiguration{
		Issuer:  "https://issuer.example",
		JwksUri: server.URL,
	}

	_, err := ValidateToken("not-a-token", configuration, "client")
	if err == nil || !strings.Contains(err.Error(), "exceeded 1 MiB") {
		t.Fatalf("ValidateToken() error = %v, want response-size error", err)
	}
}

func TestValidateTokenUsesBoundedHTTPClientForJWKS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, `{"keys":[]}`)
	}))
	defer server.Close()

	previousClient := oidcHTTPClient
	oidcHTTPClient = &http.Client{Timeout: 20 * time.Millisecond}
	defer func() { oidcHTTPClient = previousClient }()

	configuration := WellKnownConfiguration{
		Issuer:  "https://issuer.example",
		JwksUri: server.URL,
	}

	_, err := ValidateToken("not-a-token", configuration, "client")
	if err == nil {
		t.Fatal("ValidateToken() error = nil, want the JWKS fetch to time out")
	}
	// Reverting the JWKS call to a client without a deadline would let the slow
	// response through and fail later while parsing the token instead.
	if !strings.Contains(err.Error(), "fetch signing keys") {
		t.Fatalf("ValidateToken() error = %v, want a JWKS fetch failure", err)
	}
}
