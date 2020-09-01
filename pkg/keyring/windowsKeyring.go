package keyring

import (
	"fmt"
	"strconv"

	"github.com/XeroAPI/xoauth/pkg/oidc"
	"github.com/pkg/errors"
	"github.com/zalando/go-keyring"
)

type WindowsKeyRingService struct {
}

func NewWindowsKeyRingService(debug bool) (KeyRingService, error) {
	return WindowsKeyRingService{}, nil
}

func (service WindowsKeyRingService) Set(item string, value string) error {
	err := keyring.Set(KeyRingServiceName, item, value)

	if err != nil {
		return err
	}

	return nil
}

func (service WindowsKeyRingService) Get(item string) (string, error) {
	result, err := keyring.Get(KeyRingServiceName, item)

	if err != nil {
		return "", err
	}

	return result, nil
}

func (service WindowsKeyRingService) Delete(item string) error {

	err := keyring.Delete(KeyRingServiceName, fmt.Sprintf("%s.identity", item))
	err = keyring.Delete(KeyRingServiceName, fmt.Sprintf("%s.refresh", item))
	err = keyring.Delete(KeyRingServiceName, fmt.Sprintf("%s.access", item))
	err = keyring.Delete(KeyRingServiceName, fmt.Sprintf("%s.expiry", item))

	if err != nil {
		return err
	}

	return keyring.Delete(KeyRingServiceName, item)
}

// Windows Cred store 2.5kb limit requires us to reassemble the token set
func (service WindowsKeyRingService) GetTokens(item string) (oidc.TokenResultSet, error) {
	var result oidc.TokenResultSet
	var err error

	// id_token and refresh may not be present in all cases (e.g, client creds)
	identity, err := service.Get(fmt.Sprintf("%s.identity", item))
	refresh, err := service.Get(fmt.Sprintf("%s.refresh", item))

	// Since these params are optional, ignore not found errors
	if err.Error() != keyring.ErrNotFound.Error() {
		return result, err
	}

	// We can't proceed without an access_token, so here we exit
	// if we can't obtain one.
	access, err := service.Get(fmt.Sprintf("%s.access", item))
	expiry, err := service.Get(fmt.Sprintf("%s.expiry", item))

	if err != nil {
		return result, err
	}

	if access == "" {
		return result, errors.Errorf("No access token found for the connection `%s`", item)
	}

	expiryInt, convErr := strconv.ParseInt(expiry, 10, 64)

	if convErr != nil {
		return result, convErr
	}

	result = oidc.TokenResultSet{
		IdentityToken: identity,
		RefreshToken:  refresh,
		AccessToken:   access,
		ExpiresAt:     expiryInt,
	}

	return result, nil
}

// WinCreds only allows for maximum of 2.5kb in any one field.
// Here, we split the tokenset into its parts, and save them all separately.
func (service WindowsKeyRingService) SetTokens(item string, tokens oidc.TokenResultSet) error {
	var err error

	if tokens.AccessToken != "" {
		err = service.Set(fmt.Sprintf("%s.access", item), tokens.AccessToken)
		if err != nil {
			return err
		}
	}

	if tokens.IdentityToken != "" {
		err = service.Set(fmt.Sprintf("%s.identity", item), tokens.IdentityToken)
		if err != nil {
			return err
		}
	}

	if tokens.RefreshToken != "" {
		err = service.Set(fmt.Sprintf("%s.refresh", item), tokens.RefreshToken)
		if err != nil {
			return err
		}
	}

	if tokens.ExpiresAt != 0 {
		service.Set(fmt.Sprintf("%s.expiry", item), strconv.FormatInt(tokens.ExpiresAt, 10))
		if err != nil {
			return err
		}
	}

	return nil
}

func (service WindowsKeyRingService) DeleteTokens(item string) error {
	err := keyring.Delete(KeyRingServiceName, fmt.Sprintf("%s.identity", item))
	err = keyring.Delete(KeyRingServiceName, fmt.Sprintf("%s.refresh", item))
	err = keyring.Delete(KeyRingServiceName, fmt.Sprintf("%s.access", item))
	err = keyring.Delete(KeyRingServiceName, fmt.Sprintf("%s.expiry", item))

	return err
}
