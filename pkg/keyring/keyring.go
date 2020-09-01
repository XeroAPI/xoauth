package keyring

import "github.com/XeroAPI/xoauth/pkg/oidc"

const KeyRingServiceName = "com.xero.xoauth"

type KeyRingService interface {
	Set(item string, value string) error
	Get(item string) (string, error)
	Delete(item string) error
	SetTokens(item string, tokens oidc.TokenResultSet) error
	GetTokens(item string) (oidc.TokenResultSet, error)
	DeleteTokens(item string) error
}

func NewKeyRingService(debug bool, runtimeName string) (*KeyRingService, error) {
	var ring KeyRingService
	var err error

	switch runtimeName {

	case "windows":
		ring, err = NewWindowsKeyRingService(debug)

	case "darwin":
		ring, err = NewUnixKeyRingService(debug)
	default: // "linux", "freebsd", "openbsd", "netbsd"
		ring, err = NewUnixKeyRingService(debug)
	}

	return &ring, err
}
