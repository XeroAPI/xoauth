package oidc

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

func lookUpKey(keyId string, keys jwk.Set) (interface{}, error) {

	if key, ok := keys.LookupKeyID(keyId); ok {
		var rawKey interface{}

		if err := key.Raw(&rawKey); err != nil {
			return rawKey, err
		}

		return rawKey, nil
	}

	return nil, errors.New(fmt.Sprintf("unable to find key with id %s", keyId))
}

func getKeyValidatorFunc(keys jwk.Set) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		keyId, keyOk := token.Header["kid"].(string)

		if !keyOk {
			return nil, errors.New("unable to parse `kid` as string")
		}

		var rsaPubKey, keyLookupErr = lookUpKey(keyId, keys)

		if keyLookupErr != nil {
			return nil, fmt.Errorf("couldn't find key with id: %s", keyId)
		}

		log.Printf("Using public key: %s", keyId)

		return rsaPubKey, nil
	}
}

// fetchSigningKeys retrieves the JWKS under the same timeout and response size
// bound as the other OIDC calls. jwx decodes straight from the response body,
// so passing it an http.Client only supplies the timeout; the body has to be
// read and bounded here before it is parsed.
func fetchSigningKeys(jwksUri string) (jwk.Set, error) {
	response, requestErr := oidcHTTPClient.Get(jwksUri)

	if requestErr != nil {
		return nil, requestErr
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got %d when requesting %s", response.StatusCode, jwksUri)
	}

	body, readErr := ioutil.ReadAll(io.LimitReader(response.Body, maxOIDCResponseBytes+1))
	if readErr != nil {
		return nil, readErr
	}
	if len(body) > maxOIDCResponseBytes {
		return nil, errors.New("JWKS response exceeded 1 MiB")
	}

	return jwk.Parse(body)
}

func ValidateToken(tokenString string, configuration WellKnownConfiguration, clientId string) (interface{}, error) {
	// Allow up to five minutes of clock skew
	var clockToleranceSeconds = 300 * time.Second

	keys, jwksError := fetchSigningKeys(configuration.JwksUri)

	if jwksError != nil {
		return nil, fmt.Errorf("fetch signing keys: %w", jwksError)
	}

	token, tokenErr := jwt.Parse(tokenString, getKeyValidatorFunc(keys), jwt.WithLeeway(clockToleranceSeconds), jwt.WithoutAudienceValidation(), jwt.WithIssuer(configuration.Issuer))

	if tokenErr != nil {
		return nil, tokenErr
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return nil, errors.New("failed to parse claims from JWT")
	}

	if !token.Valid {
		return nil, errors.New("the JWT was invalid")
	}

	return claims, nil
}
