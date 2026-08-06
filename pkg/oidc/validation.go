package oidc

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

func lookUpKey(keyId string, keys *jwk.Set) (interface{}, error) {

	if key := keys.LookupKeyID(keyId); len(key) == 1 {
		var rawKey interface{}

		if err := key[0].Raw(&rawKey); err != nil {
			return rawKey, err
		}

		return rawKey, nil
	}

	return nil, errors.New(fmt.Sprintf("unable to find key with id %s", keyId))
}

func getKeyValidatorFunc(keys *jwk.Set) func(token *jwt.Token) (interface{}, error) {
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

// ValidateToken verifies the signature, issuer, and time-based claims of a
// JWT. It deliberately does not apply a client-ID audience check because this
// helper is also used for OAuth access tokens, whose audience is a resource
// server rather than the OAuth client.
//
// The clientId argument is retained for backwards compatibility with existing
// callers. Use ValidateIDToken when validating an OpenID Connect ID token.
func ValidateToken(tokenString string, configuration WellKnownConfiguration, clientId string) (interface{}, error) {
	return validateToken(tokenString, configuration, "")
}

// ValidateIDToken verifies an OpenID Connect ID token, including that its aud
// claim contains the relying-party client ID. For multi-audience ID tokens, it
// also requires azp to identify the same client.
func ValidateIDToken(tokenString string, configuration WellKnownConfiguration, clientId string) (interface{}, error) {
	if clientId == "" {
		return nil, errors.New("client id is required for id token audience validation")
	}

	return validateToken(tokenString, configuration, clientId)
}

func validateToken(tokenString string, configuration WellKnownConfiguration, expectedAudience string) (interface{}, error) {
	// Allow up to five minutes of clock skew
	var clockToleranceSeconds = 300 * time.Second

	keys, jwksError := jwk.FetchHTTP(configuration.JwksUri)

	if jwksError != nil {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	parserOptions := []jwt.ParserOption{
		jwt.WithLeeway(clockToleranceSeconds),
		jwt.WithIssuer(configuration.Issuer),
	}

	if expectedAudience == "" {
		parserOptions = append(parserOptions, jwt.WithoutAudienceValidation())
	} else {
		parserOptions = append(parserOptions, jwt.WithAudience(expectedAudience))
	}

	token, tokenErr := jwt.Parse(tokenString, getKeyValidatorFunc(keys), parserOptions...)

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

	if expectedAudience != "" {
		// jwt-go validates an audience only when the claim is present. An OIDC
		// ID token must include an audience, so reject tokens that omit it.
		if audience, ok := claims["aud"]; !ok || audience == nil {
			return nil, errors.New("the JWT did not include an audience claim")
		}

		if err := validateAuthorizedParty(claims, expectedAudience); err != nil {
			return nil, err
		}
	}

	return claims, nil
}

func validateAuthorizedParty(claims jwt.MapClaims, clientId string) error {
	audience, err := jwt.ParseClaimStrings(claims["aud"])
	if err != nil {
		return errors.New("the JWT included an invalid audience claim")
	}

	authorizedParty, authorizedPartyPresent := claims["azp"]
	if len(audience) > 1 && !authorizedPartyPresent {
		return errors.New("the JWT included multiple audiences without an authorized party claim")
	}

	if !authorizedPartyPresent {
		return nil
	}

	authorizedPartyString, ok := authorizedParty.(string)
	if !ok || authorizedPartyString != clientId {
		return errors.New("the JWT authorized party did not match the client id")
	}

	return nil
}
