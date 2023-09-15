package auth

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/janpuc/os-auth/pkg/config"
)

func requestToken(username, password, apiURL string, insecure bool) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	configURL := fmt.Sprintf("%s/.well-known/oauth-authorization-server", apiURL)
	req, err := http.NewRequest("GET", configURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Csrf-Token", "1")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", errors.New("Unexpected response: " + string(bodyBytes))
	}

	var config OAuthConfig
	err = json.NewDecoder(resp.Body).Decode(&config)
	if err != nil {
		return "", err
	}

	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return "", errors.New("failed to generate code verifier")
	}

	codeChallenge := generateCodeChallenge(codeVerifier)

	authData := url.Values{}
	authData.Set("client_id", "openshift-challenging-client")
	authData.Add("code_challenge", codeChallenge)
	authData.Add("code_challenge_method", "S256")
	authData.Add("redirect_uri", config.TokenEndpoint+"/implicit")
	authData.Add("response_type", "code")

	req, err = http.NewRequest("GET", config.AuthorizationEndpoint+"?"+authData.Encode(), nil)
	if err != nil {
		return "", err
	}

	basicAuth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	req.Header.Set("X-Csrf-Token", "1")
	req.Header.Set("Authorization", "Basic "+basicAuth)

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}

	locationHeader := resp.Header.Get("Location")
	parsedURL, err := url.Parse(locationHeader)
	if err != nil {
		return "", err
	}

	values := parsedURL.Query()
	code := values.Get("code")
	if code == "" {
		return "", errors.New("code parameter not found in Location header")
	}

	grantData := url.Values{}
	grantData.Set("code", code)
	grantData.Add("code_verifier", codeVerifier)
	grantData.Add("grant_type", "authorization_code")
	grantData.Add("redirect_uri", config.TokenEndpoint+"/implicit")

	req, err = http.NewRequest("POST", config.TokenEndpoint, strings.NewReader(grantData.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic b3BlbnNoaWZ0LWNoYWxsZW5naW5nLWNsaWVudDo=")

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", errors.New("Unexpected response: " + string(bodyBytes))
	}

	var token Token
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func Authenticate(creds *config.Credentials, url string, insecure bool) (*ExecCredential, error) {
	token, err := requestToken(creds.Spec.Username, creds.Spec.Password, url, insecure)
	if err != nil {
		return nil, err
	}

	execCred := &ExecCredential{
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Kind:       "ExecCredential",
		Status: struct {
			ExpirationTimestamp time.Time `json:"expirationTimestamp,omitempty"`
			Token               string    `json:"token"`
		}{
			ExpirationTimestamp: time.Now().Add(24 * time.Hour),
			Token:               token,
		},
	}

	return execCred, nil
}
