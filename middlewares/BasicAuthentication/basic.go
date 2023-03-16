package basicAuth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
)

var ErrFieldEmpty = errors.New("input field empty")

// BasicConfig sets the Basic Auth Credentials
type BasicConfig struct {
	Username string
	Password string
}

// NewBasicConfig let user set username and password accordingly
func NewBasicConfig(username, password string) (*BasicConfig, error) {
	if len(username) == 0 || len(password) == 0 {
		return nil, ErrFieldEmpty
	}
	return &BasicConfig{
		Username: username,
		Password: password,
	}, nil
}

// BasicAuthentication authenticates user credentials using Base64
func (b *BasicConfig) BasicAuthentication(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check if username and password is empty
		if b == nil {
			// if fail
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// the method from the standard library gets the content under header "Authorization",
		// then parses the base64 encoded string back into fields username and password
		username, password, ok := r.BasicAuth()
		if !ok {
			// if fail
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		usernameHash := sha256.Sum256([]byte(username))
		passwordHash := sha256.Sum256([]byte(password))

		expectedUsernameHash := sha256.Sum256([]byte(b.Username))
		expectedPasswordHash := sha256.Sum256([]byte(b.Password))

		// ConstantTimeCompare returns 1 if two byte slices are strictly equal
		usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:])
		passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:])

		// if one doesn't match, return unauthorized
		if usernameMatch != 1 || passwordMatch != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// if success, move on to the next handler
		next.ServeHTTP(w, r)
		return
	})
}
