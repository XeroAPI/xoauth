package authCodeFlow

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/XeroAPI/xoauth/pkg/db"
	"github.com/XeroAPI/xoauth/pkg/interop"
	"github.com/XeroAPI/xoauth/pkg/oidc"
	"github.com/gookit/color"
)

const callbackPath = "/callback"

func newLoopbackServer(port int, handler http.Handler) (*http.Server, net.Listener, error) {
	// RFC 8252 section 8.3 marks binding by the name "localhost" NOT RECOMMENDED:
	// a resolver that maps it to a routable address makes the callback listener
	// reachable off-host. Bind the loopback IP literal instead.
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, nil, err
	}

	// The server carries no write deadline. Go arms WriteTimeout when the
	// request header is read, and the callback handler performs the token
	// exchange and the JWKS fetch before it can render anything, so a deadline
	// here fails the success page after the tokens have already been stored. The
	// read side plus IdleTimeout still bound a slow client, and the server is
	// shut down as soon as the flow finishes.
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	return server, listener, nil
}

// newCallbackMux routes only the exact callback path and only GET requests to
// the callback handler.
func newCallbackMux(handleCallback http.HandlerFunc) *http.ServeMux {
	m := http.NewServeMux()

	m.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		handleCallback(w, r)
	})

	return m
}

type CodeFlowInteractor struct {
	wellKnownConfig oidc.WellKnownConfiguration
	database        *db.CredentialStore
	operatingSystem string
}

func NewCodeFlowInteractor(wellKnownConfig oidc.WellKnownConfiguration, database *db.CredentialStore, operatingSystem string) CodeFlowInteractor {
	return CodeFlowInteractor{
		wellKnownConfig: wellKnownConfig,
		database:        database,
		operatingSystem: operatingSystem,
	}
}

func (interactor *CodeFlowInteractor) Request(client db.OidcClient, dryRun bool, localHostPort int) {
	interactor.initRequest(client, "", "", dryRun, localHostPort)
}

func (interactor *CodeFlowInteractor) RequestWithProofOfKeyExchange(client db.OidcClient, dryRun bool, localHostPort int) {
	var verifierSet, verifierErr = oidc.GenerateCodeVerifier()

	if verifierErr != nil {
		log.Fatalln(verifierErr)
	}

	interactor.initRequest(client, verifierSet.CodeVerifier, verifierSet.CodeChallenge, dryRun, localHostPort)
}

func (interactor *CodeFlowInteractor) initRequest(client db.OidcClient, codeVerifier string, codeChallenge string, dryRun bool, localHostPort int) {
	redirectUri := fmt.Sprintf("http://localhost:%d/callback", localHostPort)
	state, stateErr := oidc.GenerateRandomStringURLSafe(24)

	if stateErr != nil {
		panic("failed to generate random state. Check that your OS has a crypto implementation available")
	}

	authorisationUrl := oidc.BuildCodeAuthorisationRequest(
		interactor.wellKnownConfig,
		client.ClientId,
		redirectUri,
		client.Scopes,
		state,
		codeChallenge,
	)

	if dryRun {
		log.Printf("%s\n%s\n",
			color.FgWhite.Sprint("Dry run, printing the authorisation request URL"),
			color.FgYellow.Sprint(authorisationUrl))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	// Open a web server to receive the redirect
	m := newCallbackMux(func(w http.ResponseWriter, r *http.Request) {
		interactor.handleOidcCallback(w, r,
			client.Alias,
			client.ClientId,
			client.ClientSecret,
			redirectUri,
			state,
			codeVerifier,
			cancel,
		)
	})

	s, listener, listenErr := newLoopbackServer(localHostPort, m)
	if listenErr != nil {
		log.Fatalf("failed to listen for OIDC callback: %v", listenErr)
	}

	serverErrors := make(chan error, 1)
	go func() {
		if err := s.Serve(listener); err != nil && err != http.ErrServerClosed {
			serverErrors <- err
		}
	}()

	log.Printf("%s", color.FgYellow.Sprintf("Opening browser window"))

	openErr := interop.OpenBrowser(interactor.operatingSystem, authorisationUrl)

	if openErr != nil {
		_ = s.Close()
		log.Fatalf("failed to open browser window %v", openErr)
	}

	select {
	case <-ctx.Done():
		// Shutdown the server when the context is canceled
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		err := s.Shutdown(shutdownCtx)

		if err != nil {
			log.Fatalln(err)
		} else {
			log.Println("")
		}
	case err := <-serverErrors:
		log.Fatalf("OIDC callback server failed: %v", err)
	}
}
