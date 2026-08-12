package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
)

const WellKnownPath = "/.well-known/openid-configuration"

func GetSchemeAndHost(urlString string) (string, error) {
	parsed, err := url.Parse(urlString)

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host), nil
}

type WellKnownConfiguration struct {
	AuthorisationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksUri               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

func GetMetadata(authority string) (WellKnownConfiguration, error) {
	var authorityBaseUrl, parseErr = GetSchemeAndHost(authority)
	var result WellKnownConfiguration

	if parseErr != nil {
		return result, parseErr
	}

	var wellKnownUrl = fmt.Sprintf("%s%s", authorityBaseUrl, WellKnownPath)

	log.Printf("Requesting OIDC metadata from %s\n", wellKnownUrl)

	response, requestErr := oidcHTTPClient.Get(wellKnownUrl)

	if requestErr != nil {
		return result, requestErr
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return result, fmt.Errorf("got %d when requesting %s", response.StatusCode, wellKnownUrl)
	}

	body, readErr := ioutil.ReadAll(io.LimitReader(response.Body, maxOIDCResponseBytes+1))
	if readErr != nil {
		return result, readErr
	}
	if len(body) > maxOIDCResponseBytes {
		return result, fmt.Errorf("OIDC metadata exceeded 1 MiB")
	}
	if decodeErr := json.Unmarshal(body, &result); decodeErr != nil {
		return result, decodeErr
	}

	log.Printf("Received OIDC metadata for authority: %s", result.Issuer)

	if result.TokenEndpoint == "" {
		return result, fmt.Errorf("no token endpoint in OIDC metadata")
	}

	if result.AuthorisationEndpoint == "" {
		return result, fmt.Errorf("no authorisation endpoint in OIDC metadata")
	}

	return result, nil
}
