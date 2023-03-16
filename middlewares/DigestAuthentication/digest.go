package DigestAuthentication

import (
	"crypto/md5"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var ErrBadChallenge = errors.New("bad challenge")

type User struct {
	Username string
	Password string
}

type Challenge struct {
	Realm  string
	Nonce  string
	Opaque string
}

type DigestAuth struct {
	User      User
	Challenge Challenge
}

type UserAuthorization struct {
	Username  string
	Realm     string
	Nonce     string
	URI       string
	Algorithm string
	Response  string
	Opaque    string
	Cnonce    string
	Qop       string
	Method    string
}

// DigestAuthenticate is a middleware implementing simple MD5 HTTP digest authentication
func (d DigestAuth) DigestAuthenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !d.Authenticate(r) {
			// the challenge set here
			w.Header().Set(
				"WWW-Authenticate",
				fmt.Sprintf(
					`Digest username=%s, realm=%s, nonce=%s, uri=%s, algorithm=md5, opague=%s`,
					d.User.Username,
					d.Challenge.Realm,
					d.Challenge.Nonce,
					r.URL.Path,
					d.Challenge.Opaque,
				))
			http.Error(w, "Unauthorized - Need Digest Authentication", http.StatusUnauthorized)
		} else {
			next.ServeHTTP(w, r)
		}
	}
}

// Authenticate matches the client response and the server response
func (d DigestAuth) Authenticate(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	userAuth, err := ParseUserAuthorization(authHeader)
	if err != nil {
		return false
	}
	userAuth.Method = r.Method
	serverHash1 := d.Hash1()
	serverHash2 := userAuth.Hash2()
	serverResponse := Response(serverHash1, serverHash2, d.Challenge.Nonce)
	return serverResponse == userAuth.Response
}

func (d DigestAuth) Hash1() string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", d.User.Username, d.Challenge.Realm, d.User.Password))))
}

func (a UserAuthorization) Hash2() string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s", a.Method, a.URI))))
}

func Response(hash1, hash2, nonce string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", hash1, nonce, hash2))))
}

// ParseUserAuthorization is a helper function that parses the digestStr from the user value of header `WWW-Authenticate`
func ParseUserAuthorization(digestStr string) (*UserAuthorization, error) {
	if strings.HasPrefix(digestStr, "Digest ") {
		auth := &UserAuthorization{}

		digestStr = digestStr[len("Digest "):]
		parts := strings.Split(digestStr, ", ")
		for _, part := range parts {
			// got something like this `realm="hello"`
			keyValue := strings.Split(part, "=")
			if len(keyValue) != 2 {
				return nil, fmt.Errorf("invalid authorization header: %s", digestStr)
			}

			key := keyValue[0]
			// remove all `"`
			value := strings.Replace(keyValue[1], `"`, "", -1)

			switch key {
			case "username":
				auth.Username = value
			case "realm":
				auth.Realm = value
			case "nonce":
				auth.Nonce = value
			case "uri":
				auth.URI = value
			case "algorithm":
				auth.Algorithm = value
			case "cnonce":
				auth.Cnonce = value
			case "qop":
				auth.Qop = value
			case "response":
				auth.Response = value
			case "opaque":
				auth.Opaque = value
			default:
				return nil, ErrBadChallenge
			}
		}
		return auth, nil
	}
	return nil, ErrBadChallenge
}
