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
	_, printErr := fmt.Fprint(os.Stdout, FormatEnvVars(clientName, tokenSet))

	if printErr != nil {
		log.Fatalln(printErr)
	}
}

func FormatEnvVars(clientName string, tokenSet oidc.TokenResultSet) string {
	envName := normaliseEnvName(clientName)

	return fmt.Sprintf(
		"export %s_ACCESS_TOKEN=%s\nexport %s_ID_TOKEN=%s\nexport %s_REFRESH_TOKEN=%s",
		envName,
		shellQuote(tokenSet.AccessToken),
		envName,
		shellQuote(tokenSet.IdentityToken),
		envName,
		shellQuote(tokenSet.RefreshToken),
	)
}

func normaliseEnvName(clientName string) string {
	name := strings.Map(func(value rune) rune {
		if value >= 'a' && value <= 'z' {
			return value - ('a' - 'A')
		}
		if (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '_' {
			return value
		}
		return '_'
	}, clientName)
	if name == "" {
		return "XOAUTH"
	}
	if name[0] >= '0' && name[0] <= '9' {
		return "_" + name
	}
	return name
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
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
