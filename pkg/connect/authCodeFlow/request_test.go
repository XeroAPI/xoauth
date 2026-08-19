package authCodeFlow

import (
	"bytes"
	"html/template"
	"log"
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
	if !ok || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("listener address = %v, want the 127.0.0.1 loopback literal", listener.Addr())
	}
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 10*time.Second || server.IdleTimeout != 30*time.Second {
		t.Fatalf("server timeouts = %v/%v/%v, want 5s/10s/30s", server.ReadHeaderTimeout, server.ReadTimeout, server.IdleTimeout)
	}
	// A write deadline is armed when the request header is read, so it would
	// expire while the handler is still exchanging the code and would fail the
	// success page after the tokens had been stored.
	if server.WriteTimeout != 0 {
		t.Fatalf("server WriteTimeout = %v, want no write deadline", server.WriteTimeout)
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

func TestRenderAndLogErrorNormalisesAndBoundsLogMessage(t *testing.T) {
	var output bytes.Buffer
	previousOutput := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	}()

	message := "useful detail\r\nforged log\x1b[31m" + strings.Repeat("x", maxCallbackErrorRunes)
	renderAndLogError(httptest.NewRecorder(), func() {}, message)

	logged := strings.TrimSuffix(output.String(), "\n")
	if strings.ContainsAny(logged, "\r\n\x1b") {
		t.Fatalf("log contains control characters: %q", logged)
	}
	if !strings.Contains(logged, "useful detail  forged log [31m") {
		t.Fatalf("log discarded safe diagnostic text: %q", logged)
	}
	prefix := "OIDC callback failed: "
	if got := len([]rune(strings.TrimPrefix(logged, prefix))); got != maxCallbackErrorRunes {
		t.Fatalf("normalised message length = %d, want %d", got, maxCallbackErrorRunes)
	}
	if !strings.HasSuffix(logged, "...") {
		t.Fatalf("bounded log message missing truncation marker: %q", logged)
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

func TestCallbackMuxServesOnlyTheCallbackPath(t *testing.T) {
	var handled int
	mux := newCallbackMux(func(w http.ResponseWriter, r *http.Request) { handled++ })

	for _, path := range []string{"/", "/callbackery", "/other"} {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want %d", path, recorder.Code, http.StatusNotFound)
		}
	}

	if handled != 0 {
		t.Fatalf("callback handler ran %d times for unrelated paths, want 0", handled)
	}

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, callbackPath, nil))

	if handled != 1 {
		t.Fatalf("callback handler ran %d times for %s, want 1", handled, callbackPath)
	}
}

func TestCallbackMuxRejectsNonGetRequests(t *testing.T) {
	var handled int
	mux := newCallbackMux(func(w http.ResponseWriter, r *http.Request) { handled++ })

	for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete} {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(method, callbackPath, nil))

		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s status = %d, want %d", method, callbackPath, recorder.Code, http.StatusMethodNotAllowed)
		}
		if allow := recorder.Header().Get("Allow"); allow != http.MethodGet {
			t.Fatalf("%s %s Allow header = %q, want %q", method, callbackPath, allow, http.MethodGet)
		}
	}

	if handled != 0 {
		t.Fatalf("callback handler ran %d times for non-GET requests, want 0", handled)
	}
}

func TestHandleOidcCallbackIgnoresAForeignState(t *testing.T) {
	interactor := CodeFlowInteractor{}
	recorder := httptest.NewRecorder()
	cancelled := false

	request := httptest.NewRequest(http.MethodGet, callbackPath+"?code=stolen&state=forged", nil)
	interactor.handleOidcCallback(
		recorder,
		request,
		"alias",
		"client",
		"secret",
		"http://127.0.0.1:8080/callback",
		"expected-state",
		"",
		func() { cancelled = true },
	)

	if cancelled {
		t.Fatal("a callback with an unexpected state cancelled the pending login")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("response status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}
