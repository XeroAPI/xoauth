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

const configLockTimeout = 5 * time.Second
const configLockPollInterval = 20 * time.Millisecond
const configLockStaleAfter = 60 * time.Second

var statFile = os.Stat
var renameFile = os.Rename
var removeFile = os.Remove
var userHomeDir = os.UserHomeDir

type OidcClient struct {
	Authority    string
	Alias        string
	GrantType    string
	ClientId     string
	ClientSecret string `json:"-"`
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

	if recoveryErr := recoverConfigFile(fileName); recoveryErr != nil {
		return recoveryErr
	}

	exists, statErr := fileExists(fileName)
	if statErr != nil {
		return statErr
	}
	if !exists {
		var seedClients = map[string]OidcClient{}

		err := store.writeClients(seedClients)

		if err != nil {
			return err
		}
	}

	return nil
}

func fileExists(filename string) (bool, error) {
	info, err := statFile(filename)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.IsDir() {
		return false, fmt.Errorf("config path is a directory: %s", filename)
	}
	return true, nil
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
	home, err := userHomeDir()

	if err != nil {
		log.Fatal(err)
	}

	path := filepath.Join(home, ConfigDirPath, ConfigFileName)

	return path
}

func (store *CredentialStore) GetClients() (map[string]OidcClient, error) {
	var clients = make(map[string]OidcClient)
	var file = store.getDbFile()

	if recoveryErr := recoverConfigFile(file); recoveryErr != nil {
		return nil, recoveryErr
	}
	exists, statErr := fileExists(file)
	if statErr != nil {
		return nil, statErr
	}
	if !exists {
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

	return writeClientsFile(fileName, clients)
}

func writeClientsFile(fileName string, clients map[string]OidcClient) error {
	jsonData, marshalErr := json.MarshalIndent(clients, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}

	directory := filepath.Dir(fileName)
	temporary, tempErr := ioutil.TempFile(directory, ".xoauth-*.tmp")
	if tempErr != nil {
		return tempErr
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}()

	if chmodErr := temporary.Chmod(0600); chmodErr != nil {
		return chmodErr
	}
	if _, writeErr := temporary.Write(jsonData); writeErr != nil {
		return writeErr
	}
	if syncErr := temporary.Sync(); syncErr != nil {
		return syncErr
	}
	if closeErr := temporary.Close(); closeErr != nil {
		return closeErr
	}

	return replaceConfigFile(temporaryName, fileName)
}

func replaceConfigFile(temporaryName string, fileName string) error {
	if recoveryErr := recoverConfigFile(fileName); recoveryErr != nil {
		return recoveryErr
	}

	if renameErr := renameFile(temporaryName, fileName); renameErr == nil {
		return nil
	} else {
		exists, statErr := fileExists(fileName)
		if statErr != nil {
			return fmt.Errorf("replace config file: %v", statErr)
		}
		if !exists {
			return fmt.Errorf("replace config file: %v", renameErr)
		}
	}

	backupName := configBackupName(fileName)
	if renameErr := renameFile(fileName, backupName); renameErr != nil {
		return renameErr
	}
	if renameErr := renameFile(temporaryName, fileName); renameErr != nil {
		if rollbackErr := renameFile(backupName, fileName); rollbackErr != nil {
			return fmt.Errorf("replace config file: %v; rollback failed: %v", renameErr, rollbackErr)
		}
		return renameErr
	}

	// The new config is installed. A backup that cannot be removed, because it is
	// locked or read-only, is stale rather than a failed write, and reporting it
	// as one aborts SaveClientWithSecret before the secret reaches the keyring.
	removeBackupFile(backupName)

	return nil
}

func removeBackupFile(backupName string) {
	if removeErr := removeFile(backupName); removeErr != nil {
		log.Printf("could not remove the stale config backup %s: %v", backupName, removeErr)
	}
}

func configBackupName(fileName string) string {
	return fileName + ".backup"
}

func recoverConfigFile(fileName string) error {
	backupName := configBackupName(fileName)
	targetExists, targetErr := fileExists(fileName)
	if targetErr != nil {
		return targetErr
	}
	backupExists, backupErr := fileExists(backupName)
	if backupErr != nil {
		return backupErr
	}

	// The config itself is intact, so a backup that cannot be removed is stale
	// rather than fatal. Failing here would brick list, connect and doctor over
	// one undeletable xoauth.json.backup.
	if targetExists && backupExists {
		removeBackupFile(backupName)
		return nil
	}
	// The config is missing, so the backup is the only copy left and a failed
	// restore genuinely has nothing to fall back to.
	if !targetExists && backupExists {
		return renameFile(backupName, fileName)
	}
	return nil
}

func configLockName(fileName string) string {
	return fileName + ".lock"
}

// lockConfig takes an exclusive advisory lock over the config file. GetClients
// followed by writeClients is a read-modify-write, so without a lock two
// concurrent invocations lose one client while its secret stays orphaned in the
// keyring. os.O_CREATE|os.O_EXCL is the portable primitive available here, and a
// lock left behind by a killed process is reclaimed once it is stale.
func lockConfig(fileName string) (func(), error) {
	if pathErr := ensurePathExists(filepath.Dir(fileName)); pathErr != nil {
		return nil, pathErr
	}

	lockName := configLockName(fileName)
	deadline := time.Now().Add(configLockTimeout)

	for {
		lock, openErr := os.OpenFile(lockName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)

		if openErr == nil {
			if closeErr := lock.Close(); closeErr != nil {
				_ = removeFile(lockName)
				return nil, closeErr
			}

			return func() {
				if removeErr := removeFile(lockName); removeErr != nil {
					log.Printf("could not release the config lock %s: %v", lockName, removeErr)
				}
			}, nil
		}

		if !os.IsExist(openErr) {
			return nil, fmt.Errorf("lock config file: %v", openErr)
		}

		if info, statErr := statFile(lockName); statErr == nil && time.Since(info.ModTime()) > configLockStaleAfter {
			if removeErr := removeFile(lockName); removeErr != nil {
				return nil, fmt.Errorf("lock config file: %v", removeErr)
			}
			continue
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for the config lock %s", lockName)
		}

		time.Sleep(configLockPollInterval)
	}
}

func (store *CredentialStore) SaveClientMetadata(client OidcClient) (bool, error) {
	unlock, lockErr := lockConfig(store.getDbFile())

	if lockErr != nil {
		return false, lockErr
	}
	defer unlock()

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
	unlock, lockErr := lockConfig(store.getDbFile())

	if lockErr != nil {
		return false, lockErr
	}
	defer unlock()

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
