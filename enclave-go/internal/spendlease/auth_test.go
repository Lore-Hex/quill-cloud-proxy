package spendlease

import (
	"crypto/sha256"
	"testing"
)

func TestAuthorizeDigestCoversExactBodyBytes(t *testing.T) {
	body := []byte(`{"value":"<>&","amount":1.0}`)
	bodyDigest := sha256.Sum256(body)
	preimage := append([]byte("tr-authorize-v1POST"+AuthorizePath), bodyDigest[:]...)
	want := sha256.Sum256(preimage)
	if got := AuthorizeDigest("post", AuthorizePath, body); got != want {
		t.Fatalf("digest = %x, want %x", got, want)
	}
	if got := AuthorizeDigest("POST", AuthorizePath, []byte(`{"value":"<>&","amount":1}`)); got == want {
		t.Fatal("different wire bytes produced the same authorize digest")
	}
}
