package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/XeroAPI/xoauth/pkg/db"
	"github.com/gookit/color"
)

func MaskString(input string) string {
	strLength := len(input)
	maskedString := strings.Repeat("•", strLength)
	return maskedString
}

func ListAll(database *db.CredentialStore, showSecrets bool) {
	allClients, err := database.GetClients()

	if err != nil {
		log.Fatalln(err)
	}

	for _, value := range allClients {
		// No client secrets in list view
		clientSecret := MaskString("shhhhh! it's a secret!")

		if showSecrets {
			loadedClient, dbErr := database.GetClientWithSecret(allClients, value.Alias)

			if dbErr != nil {
				log.Fatalln(dbErr)
			}

			clientSecret = loadedClient.ClientSecret
		}

		print_info(value, clientSecret)
	}
}

func print_info(value db.OidcClient, clientSecret string) {
	fmt.Fprintf(os.Stderr, "%s: %s\nclient_id: %s\ngrant_type: %s\nclient_secret: %s\nauthority: %s\nscopes:\n  • %s\n\n",
		color.White.Sprintf("name"),
		color.Green.Sprintf(value.Alias),
		color.Cyan.Sprintf(value.ClientId),
		color.Cyan.Sprintf(value.GrantType),
		color.Cyan.Sprintf(clientSecret),
		color.Yellow.Sprintf(value.Authority),
		strings.Join(value.Scopes, "\n  • "),
	)
}

func Info(database *db.CredentialStore, name string, showSecrets bool) {
	allClients, err := database.GetClients()

	if err != nil {
		log.Fatalln(err)
	}

	if value, ok := allClients[name]; ok {
		clientSecret := MaskString("shhhhh! it's a secret!")

		if showSecrets {
			loadedClient, dbErr := database.GetClientWithSecret(allClients, value.Alias)

			if dbErr != nil {
				log.Fatalln(dbErr)
			}

			clientSecret = loadedClient.ClientSecret
		}

		print_info(value, clientSecret)
		return
	}

	log.Fatalln(fmt.Sprintf("Couldn't find the client with the name \"%s\"", name))

}
