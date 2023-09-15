package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/janpuc/os-auth/pkg/auth"
	"github.com/janpuc/os-auth/pkg/config"
)

var apiURL string
var insecure bool

func init() {
	flag.StringVar(&apiURL, "url", "", "OpenShift API URL")
	flag.BoolVar(&insecure, "insecure", false, "Disable TLS certificate checks")
}

func main() {
	flag.Parse()

	if apiURL == "" {
		log.Fatal("URL flag (--url) is required")
	}

	creds, err := config.LoadCredentials()
	if err != nil {
		log.Fatalf("Error loading credentials: %s", err)
	}

	execCred, err := auth.Authenticate(creds, apiURL, insecure)
	if err != nil {
		log.Fatalf("Authentication failed: %s", err)
	}

	jsonData, err := json.Marshal(execCred)
	if err != nil {
		log.Fatalf("Error converting ExecCredential to JSON: %s", err)
	}

	fmt.Println(string(jsonData))
}
