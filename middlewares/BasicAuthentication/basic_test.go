package basicAuth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewBasicConfig(t *testing.T) {
	t.Run("Error-empty fields", func(t *testing.T) {
		testUsername, testPassword := "", ""
		_, err := NewBasicConfig(testUsername, testPassword)
		if err != ErrFieldEmpty {
			t.Errorf("expected error: %s, got %s\n", err.Error(), err.Error())
		}
	})

	t.Run("Success - correct config", func(t *testing.T) {
		testUsername, testPassword := "test", "test"
		bc, err := NewBasicConfig(testUsername, testPassword)
		if err != nil {
			t.Errorf("expected no error, got %s\n", err.Error())
		}

		if bc.Username != testUsername {
			t.Errorf("expected username: %s, got: %s\n", testUsername, bc.Username)
		}

		if bc.Password != testPassword {
			t.Errorf("expected password: %s, got: %s\n", testPassword, bc.Password)
		}

	})
}

func TestBasicAuthentication(t *testing.T) {
	// app basic config
	bc, err := NewBasicConfig("test", "test")
	if err != nil {
		t.Fatalf("Error creating BasicConfig: %v", err)
	}

	// handler to be served after passing the middleware
	nextHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	var username = "test1"
	var password = "test1"

	t.Run("Error-Incorrect username or password", func(t *testing.T) {
		// user request
		req := httptest.NewRequest(http.MethodGet, "/testing", nil)
		req.SetBasicAuth(username, password)

		// Use the middleware
		testHandler := bc.BasicAuthentication(nextHandler)

		// response recorder
		rr := httptest.NewRecorder()

		testHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("handler returned wrong status code: got %v want %v",
				rr.Code, http.StatusUnauthorized)
		}
	})

	username = "test"
	password = "test"

	t.Run("Success-Correct username and password", func(t *testing.T) {
		// user request
		req := httptest.NewRequest(http.MethodGet, "/testing", nil)
		req.SetBasicAuth(username, password)

		// Use the middleware
		testHandler := bc.BasicAuthentication(nextHandler)

		// response recorder
		rr := httptest.NewRecorder()

		testHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v",
				rr.Code, http.StatusOK)
		}
	})
}
