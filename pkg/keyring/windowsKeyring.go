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

var windowsKeyringSet = keyring.Set
var windowsKeyringGet = keyring.Get
var windowsKeyringDelete = keyring.Delete

func NewWindowsKeyRingService(debug bool) (KeyRingService, error) {
	return WindowsKeyRingService{}, nil
}

func (service WindowsKeyRingService) Set(item string, value string) error {
	err := windowsKeyringSet(KeyRingServiceName, item, value)

	if err != nil {
		return err
	}

	return nil
}

func (service WindowsKeyRingService) Get(item string) (string, error) {
	result, err := windowsKeyringGet(KeyRingServiceName, item)

	if err != nil {
		return "", err
	}

	return result, nil
}

func (service WindowsKeyRingService) Delete(item string) error {
	return deleteWindowsCredentials(
		fmt.Sprintf("%s.identity", item),
		fmt.Sprintf("%s.refresh", item),
		fmt.Sprintf("%s.access", item),
		fmt.Sprintf("%s.expiry", item),
		item,
	)
}

// Windows Cred store 2.5kb limit requires us to reassemble the token set
func (service WindowsKeyRingService) GetTokens(item string) (oidc.TokenResultSet, error) {
	var result oidc.TokenResultSet
	// id_token and refresh may not be present in all cases (e.g, client creds)
	identity, err := getOptionalWindowsCredential(service, fmt.Sprintf("%s.identity", item))
	if err != nil {
		return result, err
	}
	refresh, err := getOptionalWindowsCredential(service, fmt.Sprintf("%s.refresh", item))
	if err != nil {
		return result, err
	}

	// We can't proceed without an access_token, so here we exit
	// if we can't obtain one.
	access, err := service.Get(fmt.Sprintf("%s.access", item))
	if err != nil {
		return result, err
	}
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
		err = service.Set(fmt.Sprintf("%s.expiry", item), strconv.FormatInt(tokens.ExpiresAt, 10))
		if err != nil {
			return err
		}
	}

	return nil
}

func (service WindowsKeyRingService) DeleteTokens(item string) error {
	return deleteWindowsCredentials(
		fmt.Sprintf("%s.identity", item),
		fmt.Sprintf("%s.refresh", item),
		fmt.Sprintf("%s.access", item),
		fmt.Sprintf("%s.expiry", item),
	)
}

func getOptionalWindowsCredential(service WindowsKeyRingService, item string) (string, error) {
	value, err := service.Get(item)
	if err == keyring.ErrNotFound {
		return "", nil
	}
	return value, err
}

func deleteWindowsCredentials(items ...string) error {
	var firstErr error
	for _, item := range items {
		err := windowsKeyringDelete(KeyRingServiceName, item)
		if err != nil && err != keyring.ErrNotFound && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
