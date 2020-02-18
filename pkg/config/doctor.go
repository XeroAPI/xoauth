package config

import (
	"fmt"
	"github.com/xero-github/xoauth/pkg/db"
	"github.com/xero-github/xoauth/pkg/oidc"
	"log"
	"net"
)


func portFree(portNumber int) error {
	port := fmt.Sprintf("%d", portNumber)

	ln, err := net.Listen("tcp", ":" + port)

	if err != nil {
		return fmt.Errorf("can't listen on port %q: %s", port, err)
	}

	closeErr := ln.Close()

	if closeErr != nil {
		panic(closeErr)
	}

	return nil
}


func Doctor(port int) {
	// Check that we have a crypto implementation for generating random state
	prngErr := oidc.AssertAvailablePRNG()

	if prngErr != nil {
		log.Fatalf("crypto error: %v", prngErr)
	}

	// Check we can access ~/.xoauth
	dbErr := db.EnsureDbExists()

	if dbErr != nil {
		log.Fatalf("db error: %v", dbErr)
	}

	// Check that port is available
	portErr := portFree(port)

	if portErr != nil {
		log.Fatalf("port error: %v", portErr)
	}

	log.Println("✅ Looking good")
}
