package main

import (
	"log"
	"github.com/xero-github/xoauth/cmd"
)


func main() {
	// No timestamps
	log.SetFlags(0)

	cmd.Execute()
}
