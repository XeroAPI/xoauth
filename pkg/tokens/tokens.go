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

func ShowTokens(clientName string, exportToEnv bool, forceRefresh bool) {
	exists, existsErr := db.ClientExists(clientName)

	if existsErr != nil || !exists {
		log.Fatalln("Client doesn't exist")
	}

	tokenString, tokenErr := db.GetTokens(clientName)

	if tokenErr != nil {
		log.Fatalln(tokenErr)
	}

	if tokenString == "" {
		log.Fatalln("token set is not valid JSON.")
	}

	var tokenSet oidc.TokenResultSet

	tokenParseErr := json.Unmarshal([]byte(tokenString), &tokenSet)

	if tokenParseErr != nil {
		log.Fatalln(tokenParseErr)
	}

	if tokenSet.ExpiresAt <= time.Now().Unix() || forceRefresh {
		var err error

		tokenSet, err = Refresh(clientName, tokenSet)

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

	log.Printf("%s", tokenSerialised)
}

func Refresh(clientName string, tokenSet oidc.TokenResultSet) (oidc.TokenResultSet, error) {
	allClients, allClientsErr := db.GetClients()
	if allClientsErr != nil {
		log.Fatalln(allClientsErr)
	}

	clientConfig, err := db.GetClientWithSecret(allClients, clientName)

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

	var serialised, marshalErr = json.MarshalIndent(tokenSet, "", " ")

	if marshalErr != nil {
		return tokenSet, marshalErr
	}

	_, saveErr := db.SaveTokens(clientName, string(serialised))

	if saveErr != nil {
		return tokenSet, saveErr
	}

	return tokenSet, nil
}
