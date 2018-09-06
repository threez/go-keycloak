package keycloak

import "net/http"

// SessionStore is the interface to implement to provide a store implementation
// to the keycloak middleware
type SessionStore interface {
	// NewSession function gets called after successful session creation
	// the passed response write and request object can be used to handle the
	// connection directly
	NewSession(http.ResponseWriter, *http.Request, http.Handler, *Session)

	// GetSession must return the session for the given request, if no session
	// is provided the user will be redirected to keycloak to authenticate
	GetSession(*http.Request) (*Session, error)

	// DeleteSession function gets called on logout
	DeleteSession(*Session)
}
