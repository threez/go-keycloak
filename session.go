package keycloak

import (
	"context"
	"fmt"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// key used to hide the session in the context object
type keycloakKey int

var sessionKey keycloakKey = 1

// Session with ID and oauth2 token
type Session struct {
	ID      string // session_state
	Token   *oauth2.Token
	IDToken *oidc.IDToken
}

// RawOpenIDToken returns the openid token or an empty string
func (s *Session) RawOpenIDToken() string {
	token, ok := s.Token.Extra("id_token").(string)
	if !ok {
		return ""
	}
	return token
}

// StandardClaims parses and returns the standard claims of the session
func (s *Session) StandardClaims() (*StandardClaims, error) {
	var claims StandardClaims
	if err := s.IDToken.Claims(&claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// Claims unmarshals the raw JSON payload of the ID Token into a provided struct.
func (s *Session) Claims(v interface{}) error {
	if s.IDToken != nil {
		return s.IDToken.Claims(v)
	} else {
		return fmt.Errorf("No IDToken present")
	}
}

// GetSession returns the session from the current context
func GetSession(ctx context.Context) *Session {
	s, ok := ctx.Value(sessionKey).(*Session)
	if !ok {
		return nil
	}
	return s
}
