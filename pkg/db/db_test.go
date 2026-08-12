package db

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileExistsPropagatesStatErrors(t *testing.T) {
	previousStat := statFile
	statFile = func(string) (os.FileInfo, error) {
		return nil, errors.New("permission denied")
	}
	defer func() { statFile = previousStat }()

	exists, err := fileExists("config")
	if exists || err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("fileExists() = %v, %v; want propagated stat error", exists, err)
	}
}

func TestEnsureDbExistsDoesNotReplaceConfigAfterStatError(t *testing.T) {
	directory, err := ioutil.TempDir("", "xoauth-db-stat-")
	if err != nil {
		t.Fatalf("create temporary directory: %v", err)
	}
	defer os.RemoveAll(directory)

	previousHome := userHomeDir
	previousStat := statFile
	userHomeDir = func() (string, error) { return directory, nil }
	statFile = func(path string) (os.FileInfo, error) {
		if path == filepath.Join(directory, ConfigDirPath, ConfigFileName) {
			return nil, errors.New("injected stat failure")
		}
		return os.Stat(path)
	}
	defer func() {
		userHomeDir = previousHome
		statFile = previousStat
	}()

	store := &CredentialStore{}
	if err := store.EnsureDbExists(); err == nil || !strings.Contains(err.Error(), "injected stat failure") {
		t.Fatalf("EnsureDbExists() error = %v, want propagated stat failure", err)
	}
	if _, err := os.Stat(filepath.Join(directory, ConfigDirPath, ConfigFileName)); !os.IsNotExist(err) {
		t.Fatalf("config was created after stat failure: %v", err)
	}
}

func TestRecoverConfigFileRestoresDeterministicBackup(t *testing.T) {
	directory, err := ioutil.TempDir("", "xoauth-db-recovery-")
	if err != nil {
		t.Fatalf("create temporary directory: %v", err)
	}
	defer os.RemoveAll(directory)

	fileName := filepath.Join(directory, ConfigFileName)
	backupName := configBackupName(fileName)
	if err := ioutil.WriteFile(backupName, []byte(`{"old":true}`), 0600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}

	if err := recoverConfigFile(fileName); err != nil {
		t.Fatalf("recoverConfigFile() error = %v", err)
	}
	data, err := ioutil.ReadFile(fileName)
	if err != nil || string(data) != `{"old":true}` {
		t.Fatalf("recovered config = %q, %v", data, err)
	}
	if _, err := os.Stat(backupName); !os.IsNotExist(err) {
		t.Fatalf("backup still exists after recovery: %v", err)
	}
}

func TestReplaceConfigFileRollsBackFailedInstall(t *testing.T) {
	directory, err := ioutil.TempDir("", "xoauth-db-rollback-")
	if err != nil {
		t.Fatalf("create temporary directory: %v", err)
	}
	defer os.RemoveAll(directory)

	fileName := filepath.Join(directory, ConfigFileName)
	temporaryName := filepath.Join(directory, "new.tmp")
	if err := ioutil.WriteFile(fileName, []byte("old"), 0600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if err := ioutil.WriteFile(temporaryName, []byte("new"), 0600); err != nil {
		t.Fatalf("seed temporary config: %v", err)
	}

	previousRename := renameFile
	calls := 0
	renameFile = func(oldPath, newPath string) error {
		calls++
		if calls == 1 || calls == 3 {
			return errors.New("injected rename failure")
		}
		return os.Rename(oldPath, newPath)
	}
	defer func() { renameFile = previousRename }()

	if err := replaceConfigFile(temporaryName, fileName); err == nil {
		t.Fatal("replaceConfigFile() error = nil, want injected failure")
	}
	data, err := ioutil.ReadFile(fileName)
	if err != nil || string(data) != "old" {
		t.Fatalf("config after rollback = %q, %v; want old content", data, err)
	}
}

func TestWriteClientsFileReplacesExistingConfigWithoutSecrets(t *testing.T) {
	directory, err := ioutil.TempDir("", "xoauth-db-test-")
	if err != nil {
		t.Fatalf("create temporary directory: %v", err)
	}
	defer os.RemoveAll(directory)

	fileName := filepath.Join(directory, ConfigFileName)
	if err := ioutil.WriteFile(fileName, []byte(`{"old":true}`), 0666); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	clients := map[string]OidcClient{
		"client": {
			Alias:        "client",
			ClientId:     "client-id",
			ClientSecret: "must-not-be-written",
		},
	}
	if err := writeClientsFile(fileName, clients); err != nil {
		t.Fatalf("writeClientsFile() error = %v", err)
	}

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(data), "must-not-be-written") || strings.Contains(string(data), "ClientSecret") {
		t.Fatalf("config contains client secret: %s", data)
	}
	if !strings.Contains(string(data), "client-id") {
		t.Fatalf("config did not contain client metadata: %s", data)
	}

	temporaryFiles, err := filepath.Glob(filepath.Join(directory, ".xoauth-*.tmp"))
	if err != nil {
		t.Fatalf("glob temporary files: %v", err)
	}
	if len(temporaryFiles) != 0 {
		t.Fatalf("temporary files remain after replacement: %v", temporaryFiles)
	}
}
