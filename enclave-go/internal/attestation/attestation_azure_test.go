//go:build cloud_azure

package attestation

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func TestReportDataIsTheFullSha512OfRuntimeData(t *testing.T) {
	// SEV-SNP REPORT_DATA is exactly 64 bytes. If this ever produced a
	// different length the hardware would silently zero-pad or reject, and
	// the verifier's recomputation would stop matching.
	req, err := buildTokenRequest([]byte("l"), []byte("d"), []byte("n"), []byte("c"))
	if err != nil {
		t.Fatalf("buildTokenRequest: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(req.RuntimeData)
	if err != nil {
		t.Fatalf("decode runtime_data: %v", err)
	}
	reportData, err := base64.StdEncoding.DecodeString(req.ReportData)
	if err != nil {
		t.Fatalf("decode report_data: %v", err)
	}
	if len(reportData) != 64 {
		t.Fatalf("report_data must be 64 bytes, got %d", len(reportData))
	}
	want := sha512.Sum512(raw)
	if string(reportData) != string(want[:]) {
		t.Error("report_data is not SHA-512 of runtime_data; verifier could not recompute it")
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
		if other.ReportData == base.ReportData {
			t.Errorf("changing %s did not change report_data", name)
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
