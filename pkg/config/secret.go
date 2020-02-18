package config

import (
	"errors"
	"github.com/spf13/cobra"
	"log"
	"github.com/xero-github/xoauth/pkg/db"

)

func ValidateSecretCmdArgs(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return errors.New("please supply a client name, e.g, `xero`")
	}

	if len(args) < 2 {
		return errors.New("please supply a client secret, e.g, `secret`")
	}

	return nil
}


func UpdateSecret(clientName string, clientSecret string) {
	allClients, clientsErr := db.GetClients()

	if clientsErr != nil {
		log.Fatal(clientsErr)
	}

	client, clientErr := db.GetClientWithoutSecret(allClients, clientName)

	if clientErr != nil {
		log.Fatal(clientErr)
	}

	_, secretErr := db.SetClientSecret(client.Alias, clientSecret)

	if secretErr != nil {
		log.Fatal(secretErr)
	}

	log.Printf("Updated client secret for %s\n", client.Alias)
}
