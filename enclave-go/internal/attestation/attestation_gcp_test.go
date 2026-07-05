//go:build cloud_gcp

package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestGetIncludesChannelBindingNonce(t *testing.T) {
	leafDER := []byte("leaf")
	deviceBlob := []byte("devices")
	callerNonce := []byte("caller")
	channelBinding := []byte("tls-exporter")
	token := getWithCapturedNonces(t, leafDER, deviceBlob, callerNonce, channelBinding)
	nonces := fakeJWTNonces(t, token)

	leafFP := sha256.Sum256(leafDER)
	deviceHash := sha256.Sum256(deviceBlob)
	for _, want := range []string{
		hex.EncodeToString(leafFP[:]),
		hex.EncodeToString(deviceHash[:]),
		hex.EncodeToString(channelBinding),
		hex.EncodeToString(callerNonce),
	} {
		if !slices.Contains(nonces, want) {
			t.Fatalf("nonce %s absent from %v", want, nonces)
		}
	}
}

func TestGetNilChannelBindingPreservesLegacyNonceShape(t *testing.T) {
	leafDER := []byte("leaf")
	deviceBlob := []byte("devices")
	token := getWithCapturedNonces(t, leafDER, deviceBlob, nil, nil)
	nonces := fakeJWTNonces(t, token)

	leafFP := sha256.Sum256(leafDER)
	deviceHash := sha256.Sum256(deviceBlob)
	wantNonces := []string{
		hex.EncodeToString(leafFP[:]),
		hex.EncodeToString(deviceHash[:]),
	}
	if !slices.Equal(nonces, wantNonces) {
		t.Fatalf("nonces = %v, want legacy %v", nonces, wantNonces)
	}
	wantToken := fakeJWT(t, wantNonces)
	if string(token) != string(wantToken) {
		t.Fatalf("token = %q, want legacy token %q", token, wantToken)
	}
}

func TestGetKeepsCallerNonceDistinctFromExporter(t *testing.T) {
	attackerNonce := []byte("attacker-controlled")
	serverExporter := []byte("server-derived-exporter")
	token := getWithCapturedNonces(t, []byte("leaf"), []byte("devices"), attackerNonce, serverExporter)
	nonces := fakeJWTNonces(t, token)

	exporterHex := hex.EncodeToString(serverExporter)
	attackerHex := hex.EncodeToString(attackerNonce)
	if !slices.Contains(nonces, exporterHex) {
		t.Fatalf("server exporter nonce %s absent from %v", exporterHex, nonces)
	}
	if !slices.Contains(nonces, attackerHex) {
		t.Fatalf("caller nonce %s absent from %v", attackerHex, nonces)
	}
	if slices.Index(nonces, exporterHex) >= slices.Index(nonces, attackerHex) {
		t.Fatalf("exporter nonce must be committed before caller nonce: %v", nonces)
	}
}

func getWithCapturedNonces(t *testing.T, leafDER, deviceBlob, nonce, channelBinding []byte) []byte {
	t.Helper()
	oldRequestToken := requestToken
	defer func() { requestToken = oldRequestToken }()

	requestToken = func(body []byte) ([]byte, error) {
		var req tokenRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal token request: %v", err)
		}
		return fakeJWT(t, req.Nonces), nil
	}

	token, err := Get(leafDER, deviceBlob, nonce, channelBinding)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return token
}

func fakeJWT(t *testing.T, nonces []string) []byte {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "none"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(map[string][]string{"eat_nonce": nonces})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return []byte(base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".sig")
}

func fakeJWTNonces(t *testing.T, token []byte) []string {
	t.Helper()
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		t.Fatalf("fake JWT has %d parts: %q", len(parts), token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var decoded struct {
		Nonces []string `json:"eat_nonce"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return decoded.Nonces
}
