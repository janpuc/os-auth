package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

func LoadCredentials() (*Credentials, error) {
	filePath := os.ExpandEnv("$HOME/.os-auth/credentials")
	// filePath := os.ExpandEnv("$PWD/credentials.yaml")
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var creds Credentials
	err = yaml.Unmarshal(fileContent, &creds)
	if err != nil {
		return nil, err
	}

	return &creds, nil
}
