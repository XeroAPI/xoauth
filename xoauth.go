package main

import (
	"log"

	"github.com/XeroAPI/xoauth/cmd"
)

func main() {
	// No timestamps
	log.SetFlags(0)

	cmd.Execute()
}
