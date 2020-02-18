package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
)

// Adapted from https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb

func AssertAvailablePRNG() error {
	// Assert that a cryptographically secure PRNG is available.
	// Panic otherwise.
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return fmt.Errorf("crypto/rand is unavailable: Read() failed with %#v", err)
	}
	return nil
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}


func GenerateRandomStringURLSafe(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	return base64.URLEncoding.EncodeToString(b), err
}


func GeneratePkceString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-._~"
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes), nil
}


func GetRandomNumberBetween(min int, max int) (int, error) {
	if min >= math.MaxInt32 || max >= math.MaxInt32 {
		return 0, errors.New("this method can only be used to generate a 32 bit random number")
	}

	result, err := rand.Int(rand.Reader, big.NewInt(int64(max - min)))
	if err != nil {
		return 0, err
	}

	return int(result.Int64()) + min, nil
}

func GenerateBase64Sha256Hash(input string) string {
	hashFunc := sha256.New()
	hashFunc.Write([]byte(input))

	var hashBytes = hashFunc.Sum([]byte{})
	var hashStr = base64.RawURLEncoding.EncodeToString(hashBytes)

	return hashStr
}
