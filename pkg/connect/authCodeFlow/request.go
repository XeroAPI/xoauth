package authCodeFlow

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/XeroAPI/xoauth/pkg/db"
	"github.com/XeroAPI/xoauth/pkg/interop"
	"github.com/XeroAPI/xoauth/pkg/oidc"
	"github.com/gookit/color"
)

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

	m := http.NewServeMux()
	s := http.Server{Addr: fmt.Sprintf(":%d", localHostPort), Handler: m}
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	// Open a web server to receive the redirect
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

	log.Printf("%s", color.FgYellow.Sprintf("Opening browser window"))

	openErr := interop.OpenBrowser(interactor.operatingSystem, authorisationUrl)

	if openErr != nil {
		log.Fatalf("failed to open browser window %v", openErr)
	}

	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	select {
	case <-ctx.Done():
		// Shutdown the server when the context is canceled
		err := s.Shutdown(ctx)

		if err != nil && err != context.Canceled {
			log.Fatalln(err)
		} else {
			log.Println("")
		}
	}
}
