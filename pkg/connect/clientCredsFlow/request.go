package clientCredsFlow

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/XeroAPI/xoauth/pkg/db"
	"github.com/XeroAPI/xoauth/pkg/oidc"
	"github.com/gookit/color"
)

func Request(wellKnownConfig oidc.WellKnownConfiguration, client db.OidcClient, dryRun bool) {
	var scopes = strings.Join(client.Scopes, " ")

	var tokenResult, tokenErr = oidc.RequestWithClientCredentials(wellKnownConfig.TokenEndpoint, client.ClientId, client.ClientSecret, scopes)

	if tokenErr != nil {
		log.Fatalln(tokenErr)
	}

	log.Println("Validating access token")

	var _, validateErr = oidc.ValidateToken(tokenResult.AccessToken, wellKnownConfig)

	if validateErr != nil {
		log.Fatalln(validateErr)
	}

	jsonData, jsonErr := json.MarshalIndent(tokenResult, "", "    ")

	log.Print("Storing tokens in local keychain")
	_, tokenSaveErr := db.SaveTokens(client.Alias, string(jsonData))

	// Can fail with warning
	if tokenSaveErr != nil {
		log.Printf("%s: %v",
			color.Yellow.Sprintf("failed to save tokens to keychain"),
			tokenSaveErr,
		)
	}

	if jsonErr != nil {
		log.Fatalln(jsonErr)
	}
	_, finalWriteErr := fmt.Fprintf(os.Stdout, string(jsonData))

	if finalWriteErr != nil {
		log.Fatalln(finalWriteErr)
	}
}
