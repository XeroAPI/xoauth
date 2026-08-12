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

func TestAbsoluteExpiryCapsClockSkewForShortLivedTokens(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name      string
		expiresIn int
		want      time.Duration
	}{
		{name: "zero", expiresIn: 0, want: 0},
		{name: "negative", expiresIn: -30, want: 0},
		{name: "30 seconds", expiresIn: 30, want: 15 * time.Second},
		{name: "60 seconds", expiresIn: 60, want: 30 * time.Second},
		{name: "61 seconds", expiresIn: 61, want: 30 * time.Second},
		{name: "30 minutes", expiresIn: 30 * 60, want: 29 * time.Minute},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := now.Add(test.want).Unix()
			if got := AbsoluteExpiry(now, test.expiresIn); got != want {
				t.Fatalf("AbsoluteExpiry() = %d, want %d", got, want)
			}
		})
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

	previousClient := tokenHTTPClient
	tokenHTTPClient = &http.Client{Timeout: 20 * time.Millisecond}
	defer func() { tokenHTTPClient = previousClient }()

	err := FormPost(server.URL, "client", "secret", url.Values{}, &TokenResultSet{})
	if err == nil {
		t.Fatal("FormPost() error = nil, want timeout error")
	}
}

func TestFormPostDoesNotFollowRedirectsWithClientCredentials(t *testing.T) {
	redirected := make(chan bool, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, hasCredentials := r.BasicAuth()
		redirected <- hasCredentials
		fmt.Fprint(w, `{}`)
	}))
	defer target.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	err := FormPost(server.URL, "client", "secret", url.Values{}, &TokenResultSet{})
	if err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Fatalf("FormPost() error = %v, want redirect status error", err)
	}

	select {
	case hasCredentials := <-redirected:
		t.Fatalf("FormPost() followed redirect; credentials present = %t", hasCredentials)
	default:
	}
}
