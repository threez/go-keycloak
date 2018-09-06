package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// Config contains the Keycloak OIDC JSON format configuration
type Config struct {
	Realm            string       `json:"realm"`           // "dms"
	AuthServerURL    string       `json:"auth-server-url"` // "https://id.landgrafx.de/auth"
	SSLRequired      string       `json:"ssl-required"`    // "all"
	Resource         string       `json:"resource"`        // "dms-frontend"
	Credentials      *Credentials `json:"credentials"`
	ConfidentialPort int          `json:"confidential-port"` // 0
}

// Credentials contains the client credentials for keycloak
type Credentials struct {
	Secret string `json:"secret"` // "bc199826-e290-44e9-a6bd-8af4808e10b7"
}

// ParseConfig parses the keycloak config (Keycloak OIDC JSON) format
func ParseConfig(path string) (*Config, error) {
	var config Config
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Unable to open keycloak config: %v", err)
	}
	err = json.NewDecoder(f).Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse keycloak config: %v", err)
	}
	return &config, nil
}

// URL generates an Open ID Connect URL
func (c Config) URL() string {
	return fmt.Sprintf("%s/realms/%s", c.AuthServerURL, c.Realm)
}

// LogoutURL generates an Open ID Connect URL
func (c Config) LogoutURL(redirectURI string) string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout?redirect_uri=%s",
		c.AuthServerURL, c.Realm, url.QueryEscape(redirectURI))
}

// AccountURL generates an Open ID Connect URL
func (c Config) AccountURL(referrer string) string {
	return fmt.Sprintf("%s/realms/%s/account?referrer=%s", c.AuthServerURL, c.Realm, url.QueryEscape(referrer))
}

// Provider returns the OIDC provider for the configuration
func (c Config) Provider(ctx context.Context) (*oidc.Provider, error) {
	return oidc.NewProvider(ctx, c.URL())
}

// OAuth2 configure an OpenID Connect aware OAuth2 client.
func (c Config) OAuth2(provider *oidc.Provider, redirectURL string, scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.Resource,
		ClientSecret: c.Credentials.Secret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}
}
