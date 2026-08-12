package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxOIDCResponseBytes = 1024 * 1024

var oidcHTTPClient = &http.Client{Timeout: 15 * time.Second}
var tokenHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type TokenResultSet struct {
	AccessToken   string `json:"access_token"`
	IdentityToken string `json:"id_token"`
	RefreshToken  string `json:"refresh_token"`
	TokenType     string `json:"token_type"`
	ExpiresIn     int    `json:"expires_in"`
	ExpiresAt     int64  `json:"expires_at"`
}

type AccessTokenResultSet struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	ExpiresAt   int64  `json:"expires_at"`
}

func BuildCodeAuthorisationRequest(configuration WellKnownConfiguration, clientId string, redirectUri string, scopes []string, state string, codeChallenge string) string {
	urlToBuild, urlErr := url.Parse(configuration.AuthorisationEndpoint)

	if urlErr != nil {
		log.Fatal(urlErr)
	}

	scope := strings.Join(scopes, " ")

	q := url.Values{}
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("client_id", clientId)
	q.Add("redirect_uri", redirectUri)
	q.Add("scope", scope)
	q.Add("state", state)

	if codeChallenge != "" {
		q.Add("code_challenge", codeChallenge)
		q.Add("code_challenge_method", "S256")
	}

	urlToBuild.RawQuery = q.Encode()

	return urlToBuild.String()
}

type AuthorisationResponse struct {
	Code  string
	State string
}

func ValidateAuthorisationResponse(url *url.URL, state string) (AuthorisationResponse, error) {
	var response AuthorisationResponse
	var query = url.Query()
	var code = query.Get("code")
	var stateFromQuery = query.Get("state")

	if stateFromQuery != state {
		return response, errors.New(`oidc Error: state parameters don't match`)
	}

	if code == "" {
		return response, errors.New(`oidc Error: no code in OIDC response`)
	}

	response = AuthorisationResponse{
		Code:  code,
		State: state,
	}

	return response, nil
}

func FormPost(tokenEndpoint string, clientId string, clientSecret string, formData url.Values, result interface{}) error {
	encoded := formData.Encode()
	request, requestBuildErr := http.NewRequest("POST", tokenEndpoint, strings.NewReader(encoded))

	if requestBuildErr != nil {
		return requestBuildErr
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if clientSecret != "" {
		request.SetBasicAuth(clientId, clientSecret)
	}

	response, responseErr := tokenHTTPClient.Do(request)

	if responseErr != nil {
		return fmt.Errorf("post token request: %w", responseErr)
	}
	defer response.Body.Close()

	body, readErr := ioutil.ReadAll(io.LimitReader(response.Body, maxOIDCResponseBytes+1))
	if readErr != nil {
		return fmt.Errorf("read token response: %w", readErr)
	}
	if len(body) > maxOIDCResponseBytes {
		return errors.New("token response exceeded 1 MiB")
	}

	if response.StatusCode != 200 {
		var endpointError struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &endpointError) == nil && endpointError.Error != "" {
			return fmt.Errorf("token endpoint returned status %d: %s", response.StatusCode, endpointError.Error)
		}
		return fmt.Errorf("token endpoint returned status %d", response.StatusCode)
	}

	if decodeErr := json.Unmarshal(body, result); decodeErr != nil {
		return fmt.Errorf("decode token response: %w", decodeErr)
	}

	return nil
}

func ExchangeCodeForToken(tokenEndpoint string, code string, clientId string, clientSecret string, codeVerifier string, redirectUri string) (TokenResultSet, error) {
	var result TokenResultSet

	log.Printf("Exchanging code at token endpoint: %s\n", tokenEndpoint)

	formData := url.Values{
		"code":         {code},
		"grant_type":   {"authorization_code"},
		"redirect_uri": {redirectUri},
	}

	// https://tools.ietf.org/html/rfc6749#section-4.1.3
	if codeVerifier != "" {
		formData.Add("code_verifier", codeVerifier)
	}

	// https://tools.ietf.org/html/rfc6749#section-4.1.3
	if clientSecret == "" {
		formData.Add("client_id", clientId)
	}

	var postError = FormPost(tokenEndpoint, clientId, clientSecret, formData, &result)
	if postError != nil {
		return result, postError
	}

	result.ExpiresAt = AbsoluteExpiry(time.Now(), result.ExpiresIn)

	return result, nil
}

func RequestWithClientCredentials(tokenEndpoint string, clientId string, clientSecret string, scope string) (AccessTokenResultSet, error) {
	var result AccessTokenResultSet

	log.Printf("Requesting token with client credentials grant: %s\n", tokenEndpoint)

	formData := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {scope},
	}

	var postError = FormPost(tokenEndpoint, clientId, clientSecret, formData, &result)
	if postError != nil {
		return result, postError
	}

	result.ExpiresAt = AbsoluteExpiry(time.Now(), result.ExpiresIn)

	return result, nil
}

func AbsoluteExpiry(now time.Time, expiresIn int) int64 {
	// ExpiresIn returns expiry time in seconds
	lifetime := time.Second * time.Duration(expiresIn)
	if lifetime <= 0 {
		return now.Unix()
	}
	// Account for clock skew without consuming an entire short token lifetime.
	skew := lifetime / 2
	if skew > time.Minute {
		skew = time.Minute
	}
	return now.Add(lifetime - skew).Unix()
}

type CodeVerifier struct {
	CodeVerifier  string
	CodeChallenge string
}

func GenerateCodeVerifier() (CodeVerifier, error) {
	var result CodeVerifier
	log.Println("Generating code verifier and code challenge")
	randLength, randErr := GetRandomNumberBetween(43, 128)

	if randErr != nil {
		return result, randErr
	}

	verifier, verifierErr := GeneratePkceString(randLength)

	if verifierErr != nil {
		return result, verifierErr
	}

	challenge := GenerateBase64Sha256Hash(verifier)

	result.CodeVerifier = verifier
	result.CodeChallenge = challenge

	return result, nil
}
