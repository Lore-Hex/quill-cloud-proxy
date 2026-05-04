package byokcache

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type staticTokenSource struct{}

func (staticTokenSource) Token(_ context.Context) (string, error) {
	return "token", nil
}

func TestGoogleKMSUnwrapperSendsAADAndReturnsPlaintext(t *testing.T) {
	var sawAuth string
	var sawAAD string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projects/p/locations/us/keyRings/r/cryptoKeys/k:decrypt" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		sawAuth = r.Header.Get("Authorization")
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		sawAAD = payload["additionalAuthenticatedData"]
		if payload["ciphertext"] != base64.StdEncoding.EncodeToString([]byte("wrapped")) {
			t.Fatalf("ciphertext = %q", payload["ciphertext"])
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"plaintext": base64.StdEncoding.EncodeToString(fixedDEK()),
		})
	}))
	defer server.Close()

	unwrapper := &GoogleKMSUnwrapper{
		HTTPClient:  server.Client(),
		TokenSource: staticTokenSource{},
		Endpoint:    server.URL,
	}
	dek, err := unwrapper.UnwrapDEK(
		t.Context(),
		"projects/p/locations/us/keyRings/r/cryptoKeys/k",
		[]byte("wrapped"),
		[]byte("aad"),
	)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if string(dek) != string(fixedDEK()) {
		t.Fatalf("dek = %q", dek)
	}
	if sawAuth != "Bearer token" {
		t.Fatalf("authorization = %q", sawAuth)
	}
	if sawAAD != base64.StdEncoding.EncodeToString([]byte("aad")) {
		t.Fatalf("aad = %q", sawAAD)
	}
}
