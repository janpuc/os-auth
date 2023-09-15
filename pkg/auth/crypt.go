package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func generateCodeVerifier() (string, error) {
	const codeVerifierCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	const codeVerifierLength = 43

	bytes := make([]byte, codeVerifierLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = codeVerifierCharset[b%byte(len(codeVerifierCharset))]
	}
	return string(bytes), nil
}

func generateCodeChallenge(verifier string) string {
	s := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(s[:])
}
