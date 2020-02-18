package config

import (
	"fmt"
	"github.com/gookit/color"
	"log"
	"os"
	"strings"
	"github.com/xero-github/xoauth/pkg/db"
)

func MaskString(input string) string {
	strLength := len(input)
	maskedString := strings.Repeat("•", strLength)
	return maskedString
}


func ListAll(showSecrets bool) {
	allClients, err := db.GetClients()

	if err != nil {
		panic(err)
	}

	for _, value := range allClients {
		// No client secret by default
		clientSecret := MaskString("shhhhh! it's a secret!")

		if showSecrets {
			loadedClient, dbErr := db.GetClientWithSecret(allClients, value.Alias)

			if dbErr != nil {
				log.Fatalln(dbErr)
			}

			clientSecret = loadedClient.ClientSecret
		}

		fmt.Fprintf(os.Stderr, "%s: %s\nclient_id: %s\nclient_secret: %s\nauthority: %s\nscopes:\n  • %s\n\n",
			color.White.Sprintf("name"),
			color.Green.Sprintf(value.Alias),
			color.Cyan.Sprintf(value.ClientId),
			color.Cyan.Sprintf(clientSecret),
			color.Yellow.Sprintf(value.Authority),
			strings.Join(value.Scopes, "\n  • "),
		)
	}
}

