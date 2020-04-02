package connect

import (
	"log"

	"github.com/XeroAPI/xoauth/pkg/connect/authCodeFlow"
	"github.com/XeroAPI/xoauth/pkg/connect/clientCredsFlow"
	"github.com/XeroAPI/xoauth/pkg/db"
	"github.com/XeroAPI/xoauth/pkg/oidc"
)

func Authorise(name string, dryRun bool, localHostPort int) {
	allClients, dbErr := db.GetClients()

	if dbErr != nil {
		log.Fatalln(dbErr)
	}

	var clientExists, existsErr = db.ClientExists(name)

	if existsErr != nil {
		log.Fatalln(existsErr)
	}

	if !clientExists {
		log.Fatalf("The client %q doesn't exist. Create it using `xoauth setup`.", name)
	}

	var client, clientErr = db.GetClientWithSecret(allClients, name)

	if clientErr != nil {
		panic(clientErr)
	}

	var wellKnownConfig, wellKnownErr = oidc.GetMetadata(client.Authority)

	if wellKnownErr != nil {
		panic(wellKnownErr)
	}

	switch grantType := client.GrantType; grantType {
	case oidc.PKCE:
		authCodeFlow.RequestWithProofOfKeyExchange(wellKnownConfig, client, dryRun, localHostPort)
	case oidc.AuthorisationCode:
		authCodeFlow.Request(wellKnownConfig, client, dryRun, localHostPort)
	case oidc.ClientCredentials:
		clientCredsFlow.Request(wellKnownConfig, client, dryRun)
	default:
		log.Fatal("Unsupported grant type")
	}
}
