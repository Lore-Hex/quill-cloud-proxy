//go:build cloud_azure

package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"
)

func decodeRuntimeData(t *testing.T, req tokenRequest) runtimeData {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(req.RuntimeData)
	if err != nil {
		t.Fatalf("runtime_data is not base64: %v", err)
	}
	var rd runtimeData
	if err := json.Unmarshal(raw, &rd); err != nil {
		t.Fatalf("runtime_data is not JSON: %v", err)
	}
	return rd
}

func TestBuildTokenRequestBindsAllFourInputs(t *testing.T) {
	t.Setenv("QUILL_AZURE_MAA_ENDPOINT", "https://example.eus.attest.azure.net")
	leaf := []byte("leaf-der")
	device := []byte("device-blob")
	nonce := []byte("client-nonce")
	binding := []byte("channel-binding")

	req, err := buildTokenRequest(leaf, device, nonce, binding)
	if err != nil {
		t.Fatalf("buildTokenRequest: %v", err)
	}
	rd := decodeRuntimeData(t, req)

	leafFP := sha256.Sum256(leaf)
	deviceHash := sha256.Sum256(device)
	if rd.LeafFingerprint != hex.EncodeToString(leafFP[:]) {
		t.Errorf("leaf fingerprint not bound: %q", rd.LeafFingerprint)
	}
	if rd.DeviceHash != hex.EncodeToString(deviceHash[:]) {
		t.Errorf("device hash not bound: %q", rd.DeviceHash)
	}
	// The channel binding is the G6 session-binding control: without it an
	// attestation token can be replayed onto a different TLS session.
	if rd.ChannelBinding != hex.EncodeToString(binding) {
		t.Errorf("channel binding not bound: %q", rd.ChannelBinding)
	}
	if rd.Nonce != hex.EncodeToString(nonce) {
		t.Errorf("nonce not bound: %q", rd.Nonce)
	}
}

func TestRuntimeDataKeysAreSortedSoAVerifierCanRecompute(t *testing.T) {
	// The single most fragile property in this file, and it is invisible
	// without a real token: MAA does NOT echo runtime_data as the bytes we
	// sent. It re-serialises it as a JSON object with keys in alphabetical
	// order, so a verifier recomputing sha256 over the echoed object can only
	// ever produce the sorted form. Emitting sorted bytes is what makes the
	// two sides agree. Measured against real SEV-SNP hardware 2026-08-03.
	req, err := buildTokenRequest([]byte("l"), []byte("d"), []byte("n"), []byte("c"))
	if err != nil {
		t.Fatalf("buildTokenRequest: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(req.RuntimeData)
	if err != nil {
		t.Fatalf("decode runtime_data: %v", err)
	}

	var order []string
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil { // consume '{'
		t.Fatalf("runtime_data is not a JSON object: %v", err)
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		order = append(order, key.(string))
		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			t.Fatalf("read value: %v", err)
		}
	}

	if !sort.StringsAreSorted(order) {
		t.Errorf("runtime_data keys must be emitted in sorted order, got %v; "+
			"MAA re-serialises sorted, so any other order makes every real "+
			"token fail verification", order)
	}
}

func TestNoReportDataIsSent(t *testing.T) {
	// The sidecar computes REPORT_DATA itself as sha256(runtime_data) plus 32
	// zero bytes and ignores anything we supply. An earlier draft sent a
	// SHA-512 digest, which no verifier could ever have reproduced from a real
	// token. Sending nothing keeps the one authority for that value.
	req, err := buildTokenRequest([]byte("l"), []byte("d"), []byte("n"), []byte("c"))
	if err != nil {
		t.Fatalf("buildTokenRequest: %v", err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("report_data")) {
		t.Errorf("request must not carry report_data, got %s", body)
	}
}

func TestOptionalFieldsAreOmittedWhenAbsent(t *testing.T) {
	req, err := buildTokenRequest([]byte("l"), []byte("d"), nil, nil)
	if err != nil {
		t.Fatalf("buildTokenRequest: %v", err)
	}
	rd := decodeRuntimeData(t, req)
	if rd.Nonce != "" || rd.ChannelBinding != "" {
		t.Errorf("absent inputs should stay empty, got nonce=%q binding=%q", rd.Nonce, rd.ChannelBinding)
	}
}

func TestBindingIsSensitiveToEveryInput(t *testing.T) {
	// A digest that ignored one input would let that value be swapped after
	// the fact without invalidating the report.
	base, err := buildTokenRequest([]byte("l"), []byte("d"), []byte("n"), []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutated := range map[string]struct{ l, d, n, c []byte }{
		"leaf":    {[]byte("L"), []byte("d"), []byte("n"), []byte("c")},
		"device":  {[]byte("l"), []byte("D"), []byte("n"), []byte("c")},
		"nonce":   {[]byte("l"), []byte("d"), []byte("N"), []byte("c")},
		"binding": {[]byte("l"), []byte("d"), []byte("n"), []byte("C")},
	} {
		other, err := buildTokenRequest(mutated.l, mutated.d, mutated.n, mutated.c)
		if err != nil {
			t.Fatal(err)
		}
		if other.RuntimeData == base.RuntimeData {
			t.Errorf("changing %s did not change runtime_data", name)
		}
	}
}

func TestGetRefusesWithoutAnExplicitMAAEndpoint(t *testing.T) {
	// Which MAA instance signs the token is part of the trust decision;
	// defaulting it would yield tokens that verify against the wrong
	// authority.
	t.Setenv("QUILL_AZURE_MAA_ENDPOINT", "")
	if _, err := requestTokenFromSidecar([]byte("{}")); err == nil {
		t.Fatal("expected an error when QUILL_AZURE_MAA_ENDPOINT is unset")
	}
}

func TestGetPropagatesTokenBytes(t *testing.T) {
	original := requestToken
	defer func() { requestToken = original }()
	requestToken = func(_ []byte) ([]byte, error) { return []byte("jwt-bytes"), nil }

	got, err := Get([]byte("l"), []byte("d"), nil, nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "jwt-bytes" {
		t.Errorf("Get returned %q, want the issuer's bytes verbatim", got)
	}
}
