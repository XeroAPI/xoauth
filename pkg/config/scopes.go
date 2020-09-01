package config

import (
	"errors"
	"log"
	"strings"

	"github.com/XeroAPI/xoauth/pkg/db"
	"github.com/spf13/cobra"
)

func ValidateScopeCmdArgs(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return errors.New("please supply a client name, e.g, `xero`")
	}
	if len(args) < 2 {
		return errors.New("please supply at least one scope, e.g, `accounting.read` ")
	}
	return nil
}

func AddScope(database *db.CredentialStore, clientName string, scopeNames ...string) {
	allClients, clientsErr := database.GetClients()

	if clientsErr != nil {
		log.Fatal(clientsErr)
	}

	client, clientErr := database.GetClientWithoutSecret(allClients, clientName)

	if clientErr != nil {
		log.Fatal(clientErr)
	}

	for _, scope := range scopeNames {
		if Contains(client.Scopes, scope) {
			continue
		}

		client.Scopes = append(client.Scopes, scope)
	}

	_, saveErr := database.SaveClientMetadata(client)

	if saveErr != nil {
		log.Fatal(saveErr)
	}

	log.Printf("Scopes are: \n • %s", strings.Join(client.Scopes, "\n • "))
}

func RemoveScope(database *db.CredentialStore, clientName string, scopeNames ...string) {
	allClients, clientsErr := database.GetClients()

	if clientsErr != nil {
		log.Fatal(clientsErr)
	}

	client, clientErr := database.GetClientWithoutSecret(allClients, clientName)

	if clientErr != nil {
		log.Fatal(clientErr)
	}

	var newScopes []string

	for _, scope := range client.Scopes {
		if Contains(scopeNames, scope) {
			continue
		}

		newScopes = append(newScopes, scope)
	}

	client.Scopes = newScopes

	_, saveErr := database.SaveClientMetadata(client)

	if saveErr != nil {
		log.Fatal(saveErr)
	}

	log.Printf("Scopes are: \n • %s", strings.Join(client.Scopes, "\n • "))
}
