package tokens

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/XeroAPI/xoauth/pkg/db"
	"github.com/XeroAPI/xoauth/pkg/oidc"
)

func ShowTokens(database *db.CredentialStore, clientName string, exportToEnv bool, forceRefresh bool) {
	exists, existsErr := database.ClientExists(clientName)

	if existsErr != nil || !exists {
		log.Fatalln("Client doesn't exist")
	}

	tokenSet, tokenErr := database.GetTokens(clientName)

	if tokenErr != nil {
		log.Fatalln(tokenErr)
	}

	if tokenSet.ExpiresAt <= time.Now().Unix() || forceRefresh {
		var err error

		tokenSet, err = Refresh(database, clientName, tokenSet)

		if err != nil {
			log.Fatalln(err)
		}
	}

	if exportToEnv {
		PrintEnvVars(clientName, tokenSet)
		return
	}

	PrintJson(tokenSet)
}

func PrintEnvVars(clientName string, tokenSet oidc.TokenResultSet) {
	var envName = strings.ToUpper(strings.ReplaceAll(clientName, "-", "_"))

	str := fmt.Sprintf(
		"export %s_ACCESS_TOKEN=%s %s_ID_TOKEN=%s %s_REFRESH_TOKEN=%s",
		envName,
		tokenSet.AccessToken,
		envName,
		tokenSet.IdentityToken,
		envName,
		tokenSet.RefreshToken,
	)

	_, printErr := fmt.Fprint(os.Stdout, str)

	if printErr != nil {
		log.Fatalln(printErr)
	}
}

func PrintJson(tokenSet oidc.TokenResultSet) {

	tokenSerialised, tokenSerialisedErr := json.MarshalIndent(tokenSet, "", "  ")

	if tokenSerialisedErr != nil {
		log.Fatalln(tokenSerialisedErr)
	}

	fmt.Fprintf(os.Stdout, "%s", tokenSerialised)
}

func Refresh(database *db.CredentialStore, clientName string, tokenSet oidc.TokenResultSet) (oidc.TokenResultSet, error) {
	allClients, allClientsErr := database.GetClients()
	if allClientsErr != nil {
		log.Fatalln(allClientsErr)
	}

	clientConfig, err := database.GetClientWithSecret(allClients, clientName)

	if err != nil {
		return tokenSet, err
	}

	if tokenSet.RefreshToken == "" {
		log.Fatalln("No refresh token is present in the saved credentials - unable to perform a refresh")
	}

	refreshResult, refreshErr := oidc.RefreshToken(clientConfig.Authority,
		clientConfig.ClientId,
		clientConfig.ClientSecret,
		tokenSet.RefreshToken,
	)

	if refreshErr != nil {
		return tokenSet, refreshErr
	}

	tokenSet.RefreshToken = refreshResult.RefreshToken
	tokenSet.AccessToken = refreshResult.AccessToken
	tokenSet.ExpiresIn = refreshResult.ExpiresIn
	tokenSet.ExpiresAt = oidc.AbsoluteExpiry(time.Now(), refreshResult.ExpiresIn)

	_, saveErr := database.SaveTokens(clientName, oidc.TokenResultSet{
		RefreshToken: refreshResult.RefreshToken,
		AccessToken:  refreshResult.AccessToken,
		ExpiresAt:    tokenSet.ExpiresAt,
	})

	if saveErr != nil {
		return tokenSet, saveErr
	}

	return tokenSet, nil
}

func CleanTokens(database *db.CredentialStore, clientName string) error {
	exists, existsErr := database.ClientExists(clientName)

	if existsErr != nil || !exists {
		log.Fatalln("Client doesn't exist")
	}

	err := database.DeleteTokens(clientName)

	if err != nil {
		log.Println(err)
		log.Fatalln("Error deleting tokens")
	}

	return nil
}
