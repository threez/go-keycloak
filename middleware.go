package keycloak

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// ErrorLogger that is used to log authentication errors
type ErrorLogger func(v ...interface{})

var middlewareKey keycloakKey = 2

// Middleware handles unauthenticated incoming connections,
// redirect them to keycloak
type Middleware struct {
	BaseURL      string
	PathPrefix   string
	Scopes       []string
	Logger       ErrorLogger
	SessionStore SessionStore

	config       *Config
	oauth2Config *oauth2.Config
	provider     *oidc.Provider
	oidcConfig   *oidc.Config
	verifier     *oidc.IDTokenVerifier

	redirectURI, newPath, logoutPath, accountPath string

	next http.Handler
}

// ConnectWithKeycloak using the Keycloak OIDC JSON format file at given path
func (m *Middleware) ConnectWithKeycloak(path string) error {
	c, err := ParseConfig(path)
	if err != nil {
		return err
	}
	m.config = c

	m.provider, err = c.Provider(context.Background())
	if err != nil {
		return err
	}

	m.newPath = m.PathPrefix
	m.logoutPath = m.PathPrefix + "/logout"
	m.accountPath = m.PathPrefix + "/account"
	m.redirectURI = m.BaseURL + m.newPath

	m.oauth2Config = c.OAuth2(m.provider, m.redirectURI, m.Scopes)
	m.oidcConfig = &oidc.Config{ClientID: c.Resource}
	m.verifier = m.provider.Verifier(m.oidcConfig)

	return nil
}

// Handler configures the middlewares next hop
func (m *Middleware) Handler(next http.Handler) http.Handler {
	m.next = next
	return m
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.URL.Path == m.newPath {
		q := r.URL.Query()

		// Verify the request state (CSRF protection)
		err := m.verifyRequestState(r, q, time.Now())
		if err != nil {
			m.Logger(fmt.Errorf("Invalid state, possible CSRF attack: %v", err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Create session and request oauth2 token
		session := Session{ID: q.Get("session_state")}
		session.Token, err = m.oauth2Config.Exchange(ctx, q.Get("code"))
		if err != nil {
			m.Logger(fmt.Errorf("Unable to get access token from OAuth2 server: %v", err))
			w.WriteHeader(http.StatusBadGateway)
			return
		}

		// Verify the session validity (don't trust the auth server blindly)
		err = m.verifySession(ctx, &session)
		if err != nil {
			m.Logger(fmt.Errorf("Session could not be verified: %v", err))
			w.WriteHeader(http.StatusBadGateway)
			return
		}

		m.SessionStore.NewSession(w, r, m.next, &session)
		return
	}

	// try to get the session or redirect
	session, err := m.SessionStore.GetSession(r)
	if session == nil {
		if err != nil {
			m.Logger(fmt.Errorf("Failed to get session, redirecting to keycloak: %v", err))
		}
		// there is no session redirect to keycloak
		m.RedirectToKeycloak(w, r)
		return
	}

	// check Token and refresh if required
	session.Token, err = m.oauth2Config.TokenSource(ctx, session.Token).Token()
	if err != nil {
		m.Logger(err)
		// if there is no session redirect to keycloak
		m.RedirectToKeycloak(w, r)
		return
	}

	// include the middleware and session into the context for all request handlers
	ctx = context.WithValue(ctx, middlewareKey, m)
	ctx = context.WithValue(ctx, sessionKey, session)

	if r.URL.Path == m.logoutPath {
		m.SessionStore.DeleteSession(session)
		http.Redirect(w, r, m.config.LogoutURL(m.BaseURL), http.StatusFound)
		return
	} else if r.URL.Path == m.accountPath {
		http.Redirect(w, r, m.config.AccountURL(m.BaseURL+r.URL.Path), http.StatusFound)
		return
	}

	m.next.ServeHTTP(w, r.WithContext(ctx))
}

// RedirectToKeycloak redirects the client browser to keycloak for authentication
func (m *Middleware) RedirectToKeycloak(w http.ResponseWriter, r *http.Request) {
	state := m.requestState(r, time.Now())
	http.Redirect(w, r, m.oauth2Config.AuthCodeURL(state), http.StatusFound)
}

// verify the passed session and adds id token if valid token is passed
func (m *Middleware) verifySession(ctx context.Context, session *Session) error {
	idToken, err := m.verifier.Verify(ctx, session.RawOpenIDToken())
	if err != nil {
		return err
	}
	session.IDToken = idToken
	return nil
}

// requestState takes request headers that shouldn't change between requests
// like "Accept", "Accept-Encoding", "Accept-Language" and "User-Agent" and
// uses the client id to create an HMAC.
func (m *Middleware) requestState(r *http.Request, t time.Time) string {
	timestamp := strconv.FormatInt(t.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(m.config.Credentials.Secret[:]))
	mac.Write([]byte(r.Header.Get("Accept")[:]))
	mac.Write([]byte(r.Header.Get("Accept-Encoding")[:]))
	mac.Write([]byte(r.Header.Get("Accept-Language")[:]))
	mac.Write([]byte(r.Header.Get("User-Agent")[:]))
	mac.Write([]byte(timestamp[:]))
	return timestamp + "." + hex.EncodeToString(mac.Sum(nil))
}

// verifyRequestState checks that the request state is valid, o protect against CSRF attacks
func (m *Middleware) verifyRequestState(r *http.Request, query url.Values, t time.Time) error {
	state := query.Get("state")

	// parse the request state into timestamp and token
	var timestamp int64
	var token string
	n, err := fmt.Sscanf(state, "%d.%s", &timestamp, &token)
	if n != 2 {
		return fmt.Errorf("Invalid state token: %v", err)
	}

	// check the state is not to old (simple check before doing the HMAC)
	at := time.Unix(timestamp, 0)
	if t.Sub(at).Minutes() > 5 { // give the user 5 min to login to the account
		return fmt.Errorf("The state is too old")
	}

	// verify the token validity
	desiredState := m.requestState(r, at)
	if state != desiredState {
		return fmt.Errorf("The state token is invalid")
	}

	return nil
}

// GetMiddleware returns the middleare from the current context
func GetMiddleware(ctx context.Context) *Middleware {
	m, ok := ctx.Value(middlewareKey).(*Middleware)
	if !ok {
		return nil
	}
	return m
}
