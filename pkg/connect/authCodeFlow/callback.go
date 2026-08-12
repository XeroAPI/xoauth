package authCodeFlow

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"unicode"

	"github.com/XeroAPI/xoauth/pkg/oidc"
	"github.com/gookit/color"
)

const maxCallbackErrorRunes = 512

func sanitiseCallbackError(message string) string {
	safe := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, message)
	safe = strings.TrimSpace(safe)
	if safe == "" {
		return "unknown error"
	}
	runes := []rune(safe)
	if len(runes) > maxCallbackErrorRunes {
		safe = string(runes[:maxCallbackErrorRunes-3]) + "..."
	}
	return safe
}

// renderAndLogError logs a bounded, control-free diagnostic, returns a generic browser message, then shuts down the server.
func renderAndLogError(w http.ResponseWriter, cancelFunc context.CancelFunc, errorMessage string) {
	log.Printf("OIDC callback failed: %s", sanitiseCallbackError(errorMessage))
	http.Error(w, "Authentication failed. See the terminal for details.", http.StatusBadRequest)

	cancelFunc()
}

// handleOidcCallback waits for the OIDC server to redirect to our listening web server
// It exchanges the `code` for a token set. If successful, the token set is logged to StdOut,
// and the web server is shut down gracefully
func (interactor *CodeFlowInteractor) handleOidcCallback(
	w http.ResponseWriter,
	r *http.Request,
	clientName string,
	clientId string,
	clientSecret string,
	redirectUri string,
	state string,
	codeVerifier string,
	cancel context.CancelFunc,
) {
	var authorisationResponse, err = oidc.ValidateAuthorisationResponse(r.URL, state)

	if err != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", err))
		return
	}

	log.Println("Received OIDC response")

	var result, codeExchangeErr = oidc.ExchangeCodeForToken(interactor.wellKnownConfig.TokenEndpoint, authorisationResponse.Code, clientId, clientSecret, codeVerifier, redirectUri)

	if codeExchangeErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", codeExchangeErr))
		return
	}

	log.Println("Validating token")

	var _, validateErr = oidc.ValidateToken(result.IdentityToken, interactor.wellKnownConfig, clientId)

	if validateErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", validateErr))
		return
	}

	log.Print("Storing tokens in local keychain")
	_, tokenSaveErr := interactor.database.SaveTokens(clientName, result)
	tokensStored := tokenSaveErr == nil

	// Can fail with warning
	if tokenSaveErr != nil {
		log.Printf("%s: %v",
			color.Yellow.Sprintf("failed to save tokens to keychain"),
			tokenSaveErr,
		)
	}

	jsonData, jsonMarsallErr := json.MarshalIndent(result, "", "    ")

	if jsonMarsallErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", jsonMarsallErr))
		return
	}

	_, finalWriteErr := fmt.Fprintln(os.Stdout, string(jsonData))

	if finalWriteErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", finalWriteErr))
		return
	}

	t, parseErr := template.New("credentials").Parse(TokenResultView())
	if parseErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", parseErr))
		return
	}

	viewModel := TokenResultViewModel{
		Authority: interactor.wellKnownConfig.Issuer,
		Stored:    tokensStored,
	}
	if tplErr := t.Execute(w, viewModel); tplErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", tplErr))
		return
	}

	cancel()
}
