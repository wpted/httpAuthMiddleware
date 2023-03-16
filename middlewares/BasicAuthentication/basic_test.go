package basicAuth

import "testing"

func TestNewBasicConfig(t *testing.T) {
	t.Run("Error - empty fields", func(t *testing.T) {
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

}