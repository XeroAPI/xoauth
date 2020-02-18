package config

import (
	"github.com/AlecAivazis/survey/v2"
	"github.com/xero-github/xoauth/pkg/db"
	"log"
)

func ConfirmDelete(connection string) {
	confirm := false
	prompt := &survey.Confirm{
		Message: "Are you sure you want to delete this connection?",
	}

	confirmErr := survey.AskOne(prompt, &confirm)

	if confirmErr != nil {
		log.Printf("Exiting without deleting %v\n", confirmErr)
		return
	}

	if !confirm {
		log.Printf("Exiting without deleting")
	}

	_, err := db.DeleteClient(connection)

	if err != nil {
		panic(err)
	}

	log.Println("Connection deleted")
}
