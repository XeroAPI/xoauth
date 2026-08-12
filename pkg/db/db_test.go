package db

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
