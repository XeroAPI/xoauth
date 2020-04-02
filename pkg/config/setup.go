package config

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/XeroAPI/xoauth/pkg/db"
	"github.com/XeroAPI/xoauth/pkg/oidc"
	"github.com/gookit/color"
	"github.com/spf13/cobra"
)

func validateClientId(input interface{}) error {
	var clientIdRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	if !clientIdRegex.MatchString(input.(string)) {
		return errors.New("invalid client_id")
	}

	return nil
}

func validateAuthority(val interface{}) error {
	urlObj, err := url.Parse(val.(string))

	if err != nil {
		return err
	}

	if urlObj.Scheme != "http" && urlObj.Scheme != "https" {
		return errors.New("scheme must be http or https")
	}

	return nil
}

func ValidateName(val interface{}) error {
	var aliasRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	if !aliasRegex.MatchString(val.(string)) {
		return errors.New("invalid client name")
	}

	return nil
}

func ValidateClientNameCmdArgs(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return nil
	}

	nameErr := ValidateName(args[0])

	if nameErr != nil {
		return nameErr
	}

	return nil
}

func Contains(arr []string, needle string) bool {
	for _, value := range arr {
		if value == needle {
			return true
		}
	}
	return false
}

func InteractiveSetup(clientName string, defaultPort int) {
	var aliasResult = clientName

	if aliasResult == "" {
		var aliasErr error

		prompt := &survey.Input{
			Message: "Enter a name for your client:",
		}

		aliasErr = survey.AskOne(prompt, &aliasResult, survey.WithValidator(ValidateName))

		if aliasErr != nil {
			log.Printf("Error parsing name from prompt %v\n", aliasErr)
			return
		}
	}

	exists, existsErr := db.ClientExists(aliasResult)

	if existsErr != nil {
		log.Fatal(existsErr)
	}

	if exists {
		confirmResult := false

		confirm := &survey.Confirm{
			Message: "Client already exists. Replace it?",
		}

		confirmErr := survey.AskOne(confirm, &confirmResult, survey.WithValidator(survey.Required))

		if confirmErr != nil {
			log.Printf("Exiting without saving %v\n", confirmErr)
			return
		}

		if !confirmResult {
			log.Printf("Exiting without saving")
			return
		}
	}

	var authorityResult string
	authority := &survey.Input{
		Message: "What's the Authority?",
		Default: "https://identity.xero.com",
	}

	authorityErr := survey.AskOne(authority, &authorityResult, survey.WithValidator(validateAuthority))

	if authorityErr != nil {
		log.Printf("Prompt failed %v\n", authorityErr)
		return
	}

	var clientIdResult string
	clientId := &survey.Input{
		Message: "What's your client_id?",
	}

	clientIdErr := survey.AskOne(clientId, &clientIdResult, survey.WithValidator(validateClientId))

	if clientIdErr != nil {
		log.Printf("Prompt failed %v\n", clientIdErr)
		return
	}

	var grantTypeResult string
	grantType := &survey.Select{
		Message: "Select Grant Type:",
		Options: []string{oidc.AuthorisationCode, oidc.PKCE, oidc.ClientCredentials},
	}

	grantTypeErr := survey.AskOne(grantType, &grantTypeResult)

	if grantTypeErr != nil {
		log.Printf("Prompt failed %v\n", grantTypeErr)
		return
	}

	var clientSecretLabel = "What's your client_secret?"

	if grantTypeResult == oidc.PKCE {
		clientSecretLabel = "What's your client_secret (optional)?"
	}

	var clientSecretResult string
	var clientSecretErr error

	clientSecret := &survey.Password{
		Message: clientSecretLabel,
	}

	if grantTypeResult == oidc.PKCE {
		clientSecretErr = survey.AskOne(clientSecret, &clientSecretResult)
	} else {
		clientSecretErr = survey.AskOne(clientSecret, &clientSecretResult, survey.WithValidator(survey.Required))
	}

	if clientSecretErr != nil {
		log.Printf("Prompt failed %v\n", clientSecretErr)
		return
	}

	// Set default scopes depending on the grant type
	var scopeCollection []string

	if grantTypeResult == oidc.PKCE {
		scopeCollection = []string{"openid"}
	}

	if grantTypeResult == oidc.AuthorisationCode {
		scopeCollection = []string{"openid", "offline_access"}
	}

	if grantTypeResult == oidc.ClientCredentials {
		scopeCollection = []string{}
	}

	const scopeQuit = "d"

	log.Printf("Enter scopes (type `%s` to finish) ", scopeQuit)

	var lastScope = ""

	for lastScope != scopeQuit {
		log.Printf("Scopes are %v\n", scopeCollection)

		var scopesResult string
		scopes := &survey.Input{
			Message: fmt.Sprintf("Add scope (`%s` when done)", scopeQuit),
		}

		scopesErr := survey.AskOne(scopes, &scopesResult, survey.WithValidator(survey.Required))

		if scopesErr != nil {
			log.Printf("Prompt failed %v\n", scopesErr)
			return
		}

		if scopesResult == "" {
			log.Printf("Scope can't be empty\n")
			continue
		}

		if scopesResult != scopeQuit {
			if Contains(scopeCollection, scopesResult) {
				log.Printf("Already added %q\n", scopesResult)
			} else {
				scopeCollection = append(scopeCollection, scopesResult)
			}
		}

		lastScope = scopesResult
	}

	client := db.OidcClient{
		Authority:   authorityResult,
		Alias:       aliasResult,
		GrantType:   grantTypeResult,
		ClientId:    clientIdResult,
		Scopes:      scopeCollection,
		CreatedDate: time.Now(),
	}

	var saveErr error

	_, saveErr = db.SaveClientWithSecret(client, clientSecretResult)

	if saveErr != nil {
		log.Fatalf("error creating client: %v\n", saveErr)
	}

	log.Printf("✅ Saved settings for %q\n\nAuthority: %q\nClient id: %q\nGrant type: %q\nScopes: %q\n",
		client.Alias,
		client.Authority,
		client.ClientId,
		client.GrantType,
		strings.Join(client.Scopes, ", "))

	// Helpful hints for clients that need a redirect URI
	if grantTypeResult == oidc.PKCE || grantTypeResult == oidc.AuthorisationCode {
		log.Printf("\n%s %s %s\n\n",
			color.Yellow.Sprintf("👉 Make sure you've added"),
			color.White.Sprintf(fmt.Sprintf("http://localhost:%d/callback", defaultPort)),
			color.Yellow.Sprintf("as a redirect_uri in your identity provider's portal"),
		)
	}
}
