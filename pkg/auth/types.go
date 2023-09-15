package auth

import "time"

type ExecCredential struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     struct {
		ExpirationTimestamp time.Time `json:"expirationTimestamp,omitempty"`
		Token               string    `json:"token"`
	} `json:"status"`
}

type OAuthConfig struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	ScopesSupported               []string `json:"scopes_supported"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

type Token struct {
	AccessToken string `json:"access_token"`
	ExpiriesIn  int32  `json:"expiries_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}
