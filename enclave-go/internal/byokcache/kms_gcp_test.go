package byokcache

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type kmsRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn kmsRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

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

func TestGoogleKMSUnwrapperWrapDEKSendsAADAndReturnsCiphertext(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: kmsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/v1/projects/p/locations/us/keyRings/r/cryptoKeys/k:encrypt" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		var payload map[string]string
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if payload["plaintext"] != base64.StdEncoding.EncodeToString([]byte("dek")) {
			t.Fatalf("plaintext = %q", payload["plaintext"])
		}
		if payload["additionalAuthenticatedData"] != base64.StdEncoding.EncodeToString([]byte("aad")) {
			t.Fatalf("aad = %q", payload["additionalAuthenticatedData"])
		}
		body := `{"ciphertext":"` + base64.StdEncoding.EncodeToString([]byte("wrapped")) + `"}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString(body)),
		}, nil
	})}
	wrapper := &GoogleKMSUnwrapper{
		HTTPClient:  client,
		TokenSource: staticTokenSource{},
		Endpoint:    "https://kms.invalid",
	}
	wrapped, err := wrapper.WrapDEK(
		t.Context(),
		"projects/p/locations/us/keyRings/r/cryptoKeys/k",
		[]byte("dek"),
		[]byte("aad"),
	)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if string(wrapped) != "wrapped" {
		t.Fatalf("wrapped = %q", wrapped)
	}
}
