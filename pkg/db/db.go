package db

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/XeroAPI/xoauth/pkg/keyring"
	"github.com/XeroAPI/xoauth/pkg/oidc"

	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"
)

const ConfigDirPath = ".xoauth"
const ConfigFileName = "xoauth.json"

type OidcClient struct {
	Authority    string
	Alias        string
	GrantType    string
	ClientId     string
	ClientSecret string
	CreatedDate  time.Time
	Scopes       []string
}

type CredentialStore struct {
	KeyRingService keyring.KeyRingService
}

func NewCredentialStore(ring *keyring.KeyRingService) *CredentialStore {
	return &CredentialStore{
		KeyRingService: *ring,
	}
}

func (store *CredentialStore) EnsureDbExists() error {
	fileName := store.getDbFile()
	dir := filepath.Dir(fileName)

	pathErr := ensurePathExists(dir)

	if pathErr != nil {
		return pathErr
	}

	if !fileExists(fileName) {
		var seedClients = map[string]OidcClient{}

		err := store.writeClients(seedClients)

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

func (store *CredentialStore) getDbFile() string {
	home, err := os.UserHomeDir()

	if err != nil {
		log.Fatal(err)
	}

	path := filepath.Join(home, ConfigDirPath, ConfigFileName)

	return path
}

func (store *CredentialStore) GetClients() (map[string]OidcClient, error) {
	var clients = make(map[string]OidcClient)
	var file = store.getDbFile()

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

func (store *CredentialStore) GetClientWithSecret(allClients map[string]OidcClient, name string) (OidcClient, error) {
	var client OidcClient

	client = allClients[name]

	if client.GrantType == oidc.PKCE {
		client.ClientSecret = ""
		return client, nil
	}

	secret, keyringErr := store.KeyRingService.Get(client.Alias)

	if keyringErr != nil {
		return client, keyringErr
	}

	client.ClientSecret = secret

	return client, nil
}

func (store *CredentialStore) GetClientWithoutSecret(allClients map[string]OidcClient, name string) (OidcClient, error) {
	var client OidcClient

	if client, ok := allClients[name]; ok {
		return client, nil
	}

	return client, errors.New("connection not found")
}

func (store *CredentialStore) ClientExists(name string) (bool, error) {
	clients, readErr := store.GetClients()

	if readErr != nil {
		return false, readErr
	}

	if _, ok := clients[name]; ok {
		return true, nil
	}

	return false, nil
}

func (store *CredentialStore) writeClients(clients map[string]OidcClient) error {
	fileName := store.getDbFile()
	directory := filepath.Dir(fileName)

	pathErr := ensurePathExists(directory)

	if pathErr != nil {
		return pathErr
	}

	jsonData, _ := json.MarshalIndent(clients, "", "  ")
	err := ioutil.WriteFile(fileName, jsonData, 0644)
	return err
}

func (store *CredentialStore) SaveClientMetadata(client OidcClient) (bool, error) {
	clients, readErr := store.GetClients()

	if readErr != nil {
		return false, readErr
	}

	clients[client.Alias] = client

	err := store.writeClients(clients)

	return true, err
}

func (store *CredentialStore) SetClientSecret(clientName string, secret string) (bool, error) {
	keyringErr := store.KeyRingService.Set(clientName, secret)

	if keyringErr != nil {
		return false, keyringErr
	}

	return true, nil
}

func (store *CredentialStore) DeleteClientSecret(clientName string) (bool, error) {
	keyringErr := store.KeyRingService.Delete(clientName)

	if keyringErr != nil {
		return false, keyringErr
	}

	return true, nil
}

func (store *CredentialStore) SaveClientWithSecret(client OidcClient, secret string) (bool, error) {
	_, clientErr := store.SaveClientMetadata(client)

	if clientErr != nil {
		return false, clientErr
	}

	// PKCE clients don't have secrets, so skip this step if there's no secret.
	if client.GrantType == oidc.PKCE {
		return true, nil
	}

	if secret == "" {
		return false, fmt.Errorf("No secret provided")
	}

	_, secretErr := store.SetClientSecret(client.Alias, secret)

	if secretErr != nil {
		return false, secretErr
	}

	return true, nil
}

func (store *CredentialStore) DeleteClient(clientName string) (bool, error) {
	clients, clientsErr := store.GetClients()

	if clientsErr != nil {
		return false, clientsErr
	}

	if _, ok := clients[clientName]; !ok {
		return false, errors.New("the client does not exist")
	}

	_, keyringErr := store.DeleteClientSecret(clientName)

	if keyringErr != nil {
		return false, keyringErr
	}

	tokenErr := store.DeleteTokens(clientName)

	if tokenErr != nil {
		log.Printf("No tokens to delete for %s", clientName)
	}

	delete(clients, clientName)

	err := store.writeClients(clients)

	if err != nil {
		return false, err
	}

	return true, nil
}

func (store *CredentialStore) SaveTokens(clientName string, tokenSet oidc.TokenResultSet) (bool, error) {
	keyringErr := store.KeyRingService.SetTokens(clientName, tokenSet)

	if keyringErr != nil {
		return false, keyringErr
	}

	return true, nil
}

func (store *CredentialStore) GetTokens(clientName string) (oidc.TokenResultSet, error) {
	var result oidc.TokenResultSet
	result, keyringErr := store.KeyRingService.GetTokens(clientName)

	if keyringErr != nil {
		return result, keyringErr
	}

	return result, nil
}

func (store *CredentialStore) DeleteTokens(clientName string) error {
	keyringErr := store.KeyRingService.DeleteTokens(clientName)

	if keyringErr != nil {
		return keyringErr
	}

	return nil
}
