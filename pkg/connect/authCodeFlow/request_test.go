package authCodeFlow

import (
	"html/template"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewLoopbackServerBindsOnlyToLoopback(t *testing.T) {
	server, listener, err := newLoopbackServer(0, http.NewServeMux())
	if err != nil {
		t.Fatalf("newLoopbackServer() error = %v", err)
	}
	defer listener.Close()

	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		t.Fatalf("listener address = %v, want loopback TCP address", listener.Addr())
	}
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 10*time.Second || server.WriteTimeout != 15*time.Second {
		t.Fatalf("server timeouts = %v/%v/%v, want 5s/10s/15s", server.ReadHeaderTimeout, server.ReadTimeout, server.WriteTimeout)
	}
	if server.MaxHeaderBytes != 16*1024 {
		t.Fatalf("server MaxHeaderBytes = %d, want %d", server.MaxHeaderBytes, 16*1024)
	}
}

func TestRenderAndLogErrorReturnsGenericBrowserMessage(t *testing.T) {
	recorder := httptest.NewRecorder()
	cancelled := false

	renderAndLogError(recorder, func() { cancelled = true }, "sensitive endpoint detail")

	if !cancelled {
		t.Fatal("renderAndLogError() did not cancel the callback server")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("response status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if strings.Contains(recorder.Body.String(), "sensitive endpoint detail") {
		t.Fatalf("browser response exposed internal error: %q", recorder.Body.String())
	}
}

func TestTokenResultViewDoesNotRenderCredentials(t *testing.T) {
	view, err := template.New("credentials").Parse(TokenResultView())
	if err != nil {
		t.Fatalf("parse token result view: %v", err)
	}

	var output strings.Builder
	if err := view.Execute(&output, TokenResultViewModel{Authority: "https://issuer.example", Stored: true}); err != nil {
		t.Fatalf("execute token result view: %v", err)
	}

	for _, sensitive := range []string{"Access token", "Refresh token", "Identity token", "ID Token Claims"} {
		if strings.Contains(output.String(), sensitive) {
			t.Fatalf("token result view contains sensitive section %q", sensitive)
		}
	}
}
