package oidc

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"log"
)

func lookUpKey(keyId string, keys *jwk.Set) (interface{}, error)  {

	if key := keys.LookupKeyID(keyId); len(key) == 1 {
		return key[0].Materialize()
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


func ValidateToken(tokenString string, configuration WellKnownConfiguration) (interface{}, error) {
	keys, jwksError := jwk.FetchHTTP(configuration.JwksUri)

	if jwksError != nil {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	token, tokenErr := jwt.Parse(tokenString, getKeyValidatorFunc(keys))

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

