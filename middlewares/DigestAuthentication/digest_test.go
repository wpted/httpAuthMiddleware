package DigestAuthentication

import (
	"fmt"
	"testing"
)

func TestParseDigestString(t *testing.T) {
	s := `Digest username="edward", realm="hello", nonce="hello", uri="/bye", algorithm="MD5", response="414d436187260902039014f867d08044", opaque="hello"`
	ua, err := ParseUserAuthorization(s)
	fmt.Printf("%#v", ua)
	if err != nil {
		t.Errorf("error")
	}
}
