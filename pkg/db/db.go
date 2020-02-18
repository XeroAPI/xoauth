package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xero-github/xoauth/pkg/oidc"
	"github.com/zalando/go-keyring"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"
)

const KeyRingService = "com.xero.xoauth"
const ConfigDirPath = ".xoauth"
const ConfigFileName = "xoauth.json"


type OidcClient struct {
	Authority string
	Alias string
	GrantType string
	ClientId string
	ClientSecret string
	CreatedDate time.Time
	Scopes []string
}

func EnsureDbExists() error {
	fileName := getDbFile()
	dir := filepath.Dir(fileName)

	pathErr := ensurePathExists(dir)

	if pathErr != nil {
		return pathErr
	}

	if !fileExists(fileName) {
		var seedClients = map[string]OidcClient{}

		err := writeClients(seedClients)

		if err != nil {
			return err
		}
	}

	return nil
}


func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}


func ensurePathExists(directory string) error {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		mkdirErr := os.Mkdir(directory, 0700)

		if mkdirErr != nil {
			return fmt.Errorf("unable to create directory %s: %v", directory, mkdirErr)
		}
	}
	return nil
}


func getDbFile() string {
	home, err := os.UserHomeDir()

	if err != nil {
		log.Fatal(err)
	}

	path := filepath.Join(home, ConfigDirPath, ConfigFileName)

	return path
}


func GetClients() (map[string]OidcClient, error) {
	var clients = make(map[string]OidcClient)
	var file = getDbFile()

	if !fileExists(file) {
		return clients, nil
	}

	data, err := ioutil.ReadFile(file)

	if err != nil {
		return nil, err
	}

	decodeErr := json.Unmarshal(data, &clients)

	if decodeErr != nil {
		return clients, decodeErr
	}

	return clients, nil
}

func GetClientWithSecret(allClients map[string]OidcClient, name string) (OidcClient, error) {
	var client OidcClient

	client = allClients[name]

	secret, keyringErr := keyring.Get(KeyRingService, client.Alias)

	if keyringErr != nil {
		// The secret is optional in some cases for PKCE.
		// Need to differentiate secret not found vs other keychain errors
		if keyringErr.Error() == "secret not found in keyring" && client.GrantType == oidc.PKCE {

		} else {
			return client, keyringErr
		}
	}

	client.ClientSecret = secret

	return client, nil
}


func GetClientWithoutSecret(allClients map[string]OidcClient, name string) (OidcClient, error) {
	var client OidcClient
	client = allClients[name]
	return client, nil
}


func ClientExists(name string) (bool, error) {
	clients, readErr := GetClients()

	if readErr != nil {
		return false, readErr
	}

	if _, ok := clients[name]; ok {
		return true, nil
	}

	return false, nil
}


func writeClients(clients map[string]OidcClient) error {
	fileName := getDbFile()
	directory := filepath.Dir(fileName)

	pathErr := ensurePathExists(directory)

	if pathErr != nil {
		return pathErr
	}

	jsonData, _ := json.MarshalIndent(clients, "", "  ")
	err := ioutil.WriteFile(fileName, jsonData, 0644)
	return err
}


func SaveClientMetadata(client OidcClient) (bool, error) {
	clients, readErr := GetClients()

	if readErr != nil {
		return false, readErr
	}

	clients[client.Alias] = client

	err := writeClients(clients)

	return true, err
}

func SetClientSecret(clientName string, secret string) (bool, error) {
	keyringErr := keyring.Set(KeyRingService, clientName, secret)

	if keyringErr != nil {
		return false, keyringErr
	}

	return true, nil
}

func DeleteClientSecret(clientName string) (bool, error) {
	keyringErr := keyring.Delete(KeyRingService, clientName)

	if keyringErr != nil {
		return false, keyringErr
	}

	return true, nil
}



func SaveClientWithSecret(client OidcClient, secret string) (bool, error) {
	_, clientErr := SaveClientMetadata(client)

	if clientErr != nil {
		return false, clientErr
	}

	// PKCE clients don't have secrets, so skip this step if there's no secret.
	if secret != "" {
		_, secretErr := SetClientSecret(client.Alias, secret)

		if secretErr != nil {
			return false, secretErr
		}
	}

	return true, nil
}


func DeleteClient(clientName string) (bool, error) {
	clients, clientsErr := GetClients()

	if clientsErr != nil {
		return false, clientsErr
	}

	if _, ok := clients[clientName]; !ok {
		return false, errors.New("the client does not exist")
	}

	_, keyringErr := DeleteClientSecret(clientName)

	if keyringErr != nil {
		return false, keyringErr
	}

	tokenErr := DeleteTokens(clientName)

	if tokenErr != nil {
		log.Printf("No tokens to delete for %s", clientName)
	}
	
	delete(clients, clientName)

	err := writeClients(clients)

	if err != nil {
		return false, err
	}

	return true, nil
}


func SaveTokens(clientName string, tokenData string) (bool, error) {
	var keyName = fmt.Sprintf("%s:token_set", clientName)
	keyringErr := keyring.Set(KeyRingService, keyName, tokenData)

	if keyringErr != nil {
		return false, keyringErr
	}

	return true, nil
}

func GetTokens(clientName string) (string, error) {
	var keyName = fmt.Sprintf("%s:token_set", clientName)

	data, keyringErr := keyring.Get(KeyRingService, keyName)

	if keyringErr != nil {
		return "", keyringErr
	}

	return data, nil
}

func DeleteTokens(clientName string) error {
	var keyName = fmt.Sprintf("%s:token_set", clientName)

	keyringErr := keyring.Delete(KeyRingService, keyName)

	if keyringErr != nil {
		return keyringErr
	}

	return nil
}
