package keyring

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/zalando/go-keyring"

	"github.com/XeroAPI/xoauth/pkg/oidc"
)

type UnixKeyRingService struct {
}

func NewUnixKeyRingService(debug bool) (KeyRingService, error) {
	return UnixKeyRingService{}, nil
}

func (service UnixKeyRingService) Set(item string, value string) error {
	err := keyring.Set(KeyRingServiceName, item, value)

	if err != nil {
		return err
	}

	return nil
}

func (service UnixKeyRingService) Get(item string) (string, error) {
	result, err := keyring.Get(KeyRingServiceName, item)

	if err != nil {
		return "", err
	}

	return result, nil
}

func (service UnixKeyRingService) Delete(item string) error {
	return keyring.Delete(KeyRingServiceName, item)
}

func (service UnixKeyRingService) GetTokens(item string) (oidc.TokenResultSet, error) {
	var result oidc.TokenResultSet
	var keyName = fmt.Sprintf("%s:token_set", item)

	rawData, keyingErr := service.Get(keyName)

	if keyingErr != nil {
		return result, keyingErr
	}

	unmarshalErr := json.Unmarshal([]byte(rawData), &result)

	if unmarshalErr != nil {
		return result, unmarshalErr
	}

	return result, nil
}

func (service UnixKeyRingService) SetTokens(item string, tokens oidc.TokenResultSet) error {
	var keyName = fmt.Sprintf("%s:token_set", item)

	tokenSerialised, tokenSerialisedErr := json.MarshalIndent(tokens, "", "  ")

	if tokenSerialisedErr != nil {
		log.Fatalln(tokenSerialisedErr)
	}

	return service.Set(keyName, string(tokenSerialised))
}

func (service UnixKeyRingService) DeleteTokens(item string) error {
	var keyName = fmt.Sprintf("%s:token_set", item)
	return service.Delete(keyName)
}
