package connect

import (
	"log"

	"github.com/XeroAPI/xoauth/pkg/connect/authCodeFlow"
	"github.com/XeroAPI/xoauth/pkg/connect/clientCredsFlow"
	"github.com/XeroAPI/xoauth/pkg/db"
	"github.com/XeroAPI/xoauth/pkg/oidc"
)

func Authorise(database *db.CredentialStore, name string, operatingSystem string, dryRun bool, localHostPort int) {
	allClients, dbErr := database.GetClients()

	if dbErr != nil {
		log.Fatalln(dbErr)
	}

	var clientExists, existsErr = database.ClientExists(name)

	if existsErr != nil {
		log.Fatalln(existsErr)
	}

	if !clientExists {
		log.Fatalf("The client %q doesn't exist. Create it using `xoauth setup`.", name)
	}

	var client, clientErr = database.GetClientWithSecret(allClients, name)

	if clientErr != nil {
		panic(clientErr)
	}

	var wellKnownConfig, wellKnownErr = oidc.GetMetadata(client.Authority)

	if wellKnownErr != nil {
		panic(wellKnownErr)
	}

	switch grantType := client.GrantType; grantType {
	case oidc.PKCE:
		interactor := authCodeFlow.NewCodeFlowInteractor(wellKnownConfig, database, operatingSystem)
		interactor.RequestWithProofOfKeyExchange(client, dryRun, localHostPort)
	case oidc.AuthorisationCode:
		interactor := authCodeFlow.NewCodeFlowInteractor(wellKnownConfig, database, operatingSystem)
		interactor.Request(client, dryRun, localHostPort)
	case oidc.ClientCredentials:
		interactor := clientCredsFlow.NewClientCredsFlow(wellKnownConfig, database, operatingSystem)
		interactor.Request(client, dryRun)
	default:
		log.Fatal("Unsupported grant type")
	}
}
