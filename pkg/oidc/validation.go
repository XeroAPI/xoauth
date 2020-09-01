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

func ValidateToken(tokenString string, configuration WellKnownConfiguration, clientId string) (interface{}, error) {
	// Allow up to five minutes of clock skew
	var clockToleranceSeconds = 300 * time.Second

	keys, jwksError := jwk.FetchHTTP(configuration.JwksUri)

	if jwksError != nil {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	log.Println(tokenString)

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
