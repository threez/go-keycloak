package keycloak

import (
	"net/http"
	"sync"
	"time"
)

// InsecureStore implements the SessionStore interface
// in a naive / insecure way
type InsecureStore struct {
	redirectAfterLoginURL string
	sessions              map[string]interface{}
	mu                    sync.RWMutex
}

// NewInsecureStore creates a new insecure cookie based store that
// will redirect to the passed URL after successful login
func NewInsecureStore(redirectAfterLoginURL string) *InsecureStore {
	return &InsecureStore{
		redirectAfterLoginURL: redirectAfterLoginURL,
		sessions:              make(map[string]interface{}),
	}
}

// NewSession implements SessionStore NewSession
func (s *InsecureStore) NewSession(w http.ResponseWriter, r *http.Request, next http.Handler, session *Session) {
	s.mu.Lock()
	s.sessions[session.ID] = session
	s.mu.Unlock()

	c := http.Cookie{
		Path:    "/",
		Name:    "session-id",
		Value:   session.ID,
		Expires: time.Now().Add(time.Hour),
	}
	http.SetCookie(w, &c)
	http.Redirect(w, r, s.redirectAfterLoginURL, http.StatusFound)
}

// GetSession implements SessionStore GetSession
func (s *InsecureStore) GetSession(r *http.Request) (*Session, error) {
	sessionID, err := r.Cookie("session-id")
	if err == http.ErrNoCookie {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	v, ok := s.sessions[sessionID.Value]
	s.mu.RUnlock()
	if !ok {
		return nil, nil
	}

	return v.(*Session), nil
}

// DeleteSession implements SessionStore DeleteSession
func (s *InsecureStore) DeleteSession(session *Session) {
	s.mu.Lock()
	delete(s.sessions, session.ID)
	s.mu.Unlock()
}
