package oidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAbsoluteExpiryAppliesClockSkew(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	want := now.Add(29 * time.Minute).Unix()

	if got := AbsoluteExpiry(now, 30*60); got != want {
		t.Fatalf("AbsoluteExpiry() = %d, want %d", got, want)
	}
}

func TestAbsoluteExpiryDoesNotExpireShortLivedTokenImmediately(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	want := now.Add(30 * time.Second).Unix()

	if got := AbsoluteExpiry(now, 30); got != want {
		t.Fatalf("AbsoluteExpiry() = %d, want %d", got, want)
	}
}

func TestFormPostRedactsTokenEndpointDescription(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"refresh-token-secret"}`)
	}))
	defer server.Close()

	err := FormPost(server.URL, "client", "secret", url.Values{}, &TokenResultSet{})
	if err == nil {
		t.Fatal("FormPost() error = nil, want a token endpoint error")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("FormPost() error = %q, want the OAuth error code", err)
	}
	if strings.Contains(err.Error(), "refresh-token-secret") {
		t.Fatalf("FormPost() exposed the endpoint error description: %q", err)
	}
}

func TestFormPostRejectsOversizedResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, strings.Repeat("x", maxOIDCResponseBytes+1))
	}))
	defer server.Close()

	err := FormPost(server.URL, "client", "secret", url.Values{}, &TokenResultSet{})
	if err == nil || !strings.Contains(err.Error(), "exceeded 1 MiB") {
		t.Fatalf("FormPost() error = %v, want response-size error", err)
	}
}

func TestFormPostUsesBoundedHTTPClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	previousClient := oidcHTTPClient
	oidcHTTPClient = &http.Client{Timeout: 20 * time.Millisecond}
	defer func() { oidcHTTPClient = previousClient }()

	err := FormPost(server.URL, "client", "secret", url.Values{}, &TokenResultSet{})
	if err == nil {
		t.Fatal("FormPost() error = nil, want timeout error")
	}
}
