package oidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetMetadataRejectsOversizedResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", maxOIDCResponseBytes+1))
	}))
	defer server.Close()

	_, err := GetMetadata(server.URL)
	if err == nil || !strings.Contains(err.Error(), "exceeded 1 MiB") {
		t.Fatalf("GetMetadata() error = %v, want response-size error", err)
	}
}
