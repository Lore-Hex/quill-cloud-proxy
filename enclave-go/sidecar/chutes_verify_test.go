package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

func testCertificate(t *testing.T, publicKey any, privateKey any, now time.Time) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "attestation.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func signTestES384JWT(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "ES384", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := encodedHeader + "." + encodedPayload
	digest := sha512.Sum384([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

type nrasTestServer struct {
	server         *httptest.Server
	overallPass    bool
	nonce          string
	key            *ecdsa.PrivateKey
	certDER        []byte
	now            time.Time
	mutateOverall  func(map[string]any)
	mutateDetached func(map[string]any)
}

func newNRASTestServer(t *testing.T, now time.Time, nonce string, overallPass bool) *nrasTestServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := &nrasTestServer{
		overallPass: overallPass,
		nonce:       nonce,
		key:         key,
		certDER:     testCertificate(t, &key.PublicKey, key, now),
		now:         now,
	}
	state.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
				"kid": "nras-test", "x5c": []string{base64.StdEncoding.EncodeToString(state.certDER)},
			}}})
		case "/attest":
			var request struct {
				Nonce        string `json:"nonce"`
				EvidenceList []any  `json:"evidence_list"`
				Arch         string `json:"arch"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode NRAS request: %v", err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if request.Nonce != state.nonce || request.Arch != "HOPPER" || len(request.EvidenceList) != 1 {
				t.Errorf("unexpected NRAS request: %#v", request)
			}
			timestamps := map[string]any{
				"iat": state.now.Unix(), "nbf": state.now.Add(-time.Minute).Unix(), "exp": state.now.Add(time.Hour).Unix(),
			}
			overall := map[string]any{
				"sub": "NVIDIA-PLATFORM-ATTESTATION", "eat_nonce": state.nonce,
				"x-nvidia-overall-att-result": state.overallPass,
			}
			for key, value := range timestamps {
				overall[key] = value
			}
			if state.mutateOverall != nil {
				state.mutateOverall(overall)
			}
			detached := map[string]any{
				"eat_nonce": state.nonce, "measres": "success", "secboot": true,
				"dbgstat": "disabled", "hwmodel": "NVIDIA H200",
				"x-nvidia-gpu-arch-check":                              true,
				"x-nvidia-gpu-attestation-report-cert-chain-validated": true,
				"x-nvidia-gpu-attestation-report-parsed":               true,
				"x-nvidia-gpu-attestation-report-nonce-match":          true,
				"x-nvidia-gpu-attestation-report-signature-verified":   true,
				"x-nvidia-gpu-driver-rim-signature-verified":           true,
				"x-nvidia-gpu-vbios-rim-signature-verified":            true,
				"x-nvidia-gpu-driver-rim-measurements-available":       true,
				"x-nvidia-gpu-vbios-rim-measurements-available":        true,
				"x-nvidia-gpu-vbios-index-no-conflict":                 true,
			}
			for key, value := range timestamps {
				detached[key] = value
			}
			if state.mutateDetached != nil {
				state.mutateDetached(detached)
			}
			_ = json.NewEncoder(w).Encode([]any{
				[]any{"JWT", signTestES384JWT(t, state.key, "nras-test", overall)},
				map[string]string{"GPU-0": signTestES384JWT(t, state.key, "nras-test", detached)},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return state
}

func (s *nrasTestServer) verifier() *nrasVerifier {
	return &nrasVerifier{
		client:   s.server.Client(),
		endpoint: s.server.URL + "/attest",
		jwksURL:  s.server.URL + "/jwks",
		now:      func() time.Time { return s.now },
		jwks:     make(map[string]*x509.Certificate),
	}
}

func makeTestQuote(
	t *testing.T,
	mrtd []byte,
	rtmrs [][]byte,
	reportData []byte,
	debug bool,
) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/tdx_quote_v4.dat")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	quote := parsed.(*tdxpb.QuoteV4)
	quote.TdQuoteBody.MrTd = append([]byte(nil), mrtd...)
	quote.TdQuoteBody.Rtmrs = make([][]byte, len(rtmrs))
	for index := range rtmrs {
		quote.TdQuoteBody.Rtmrs[index] = append([]byte(nil), rtmrs[index]...)
	}
	quote.TdQuoteBody.ReportData = append([]byte(nil), reportData...)
	quote.TdQuoteBody.TdAttributes = make([]byte, 8)
	if debug {
		quote.TdQuoteBody.TdAttributes[0] = 1
	}
	mutated, err := abi.QuoteToAbiBytes(quote)
	if err != nil {
		t.Fatal(err)
	}
	return mutated
}

func makeChutesVerificationRequest(
	t *testing.T,
	now time.Time,
	nonce, e2ePubkey string,
	mrtd []byte,
	rtmrs [][]byte,
	debug bool,
) (*chutesVerificationRequest, *chutesMeasurement) {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certDER := testCertificate(t, &rsaKey.PublicKey, rsaKey, now)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	binding := sha256.Sum256([]byte(nonce + e2ePubkey))
	certBinding := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	reportData := append(append([]byte(nil), binding[:]...), certBinding[:]...)
	quote := makeTestQuote(t, mrtd, rtmrs, reportData, debug)
	gpus := []chutesGPUEvidence{{Certificate: "gpu-cert", Evidence: "gpu-evidence", Arch: "HOPPER"}}
	gpuJSON, _ := json.Marshal(gpus)
	signed := signedChutesEvidence{Nonce: nonce}
	signed.Evidence.TDXQuote = base64.StdEncoding.EncodeToString(quote)
	signed.Evidence.NVTrustEvidence = string(gpuJSON)
	signedBody, _ := json.Marshal(signed)
	digest := sha256.Sum256(signedBody)
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := json.Marshal(chutesEvidence{
		InstanceID:   "instance-1",
		Certificate:  base64.StdEncoding.EncodeToString(certDER),
		Signature:    base64.StdEncoding.EncodeToString(signature),
		AttestedBody: base64.StdEncoding.EncodeToString(signedBody),
	})
	measurement := &chutesMeasurement{
		Version: "test", Name: "1xh200", MRTD: strings.ToUpper(hex.EncodeToString(mrtd)),
		RuntimeRTMRs: map[string]string{}, ExpectedGPUs: []string{"h200"}, GPUCount: 1,
	}
	for index, rtmr := range rtmrs {
		measurement.RuntimeRTMRs[fmt.Sprintf("RTMR%d", index)] = strings.ToUpper(hex.EncodeToString(rtmr))
	}
	return &chutesVerificationRequest{
		ChuteID: "chute-1", Instance: "instance-1", Nonce: nonce,
		E2EPubkey: e2ePubkey, Evidence: evidence,
	}, measurement
}

func TestChutesVerifierAcceptsOnlyFullyBoundEvidence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	nonce := strings.Repeat("ab", 32)
	e2ePubkey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 1184))
	mrtd := bytes.Repeat([]byte{1}, 48)
	rtmrs := [][]byte{
		bytes.Repeat([]byte{2}, 48), bytes.Repeat([]byte{3}, 48),
		bytes.Repeat([]byte{4}, 48), bytes.Repeat([]byte{5}, 48),
	}
	request, measurement := makeChutesVerificationRequest(t, now, nonce, e2ePubkey, mrtd, rtmrs, false)
	binding := sha256.Sum256([]byte(nonce + e2ePubkey))
	nras := newNRASTestServer(t, now, hex.EncodeToString(binding[:]), true)
	defer nras.server.Close()
	verifier := &chutesVerifier{
		measurements: []chutesMeasurement{*measurement},
		nras:         nras.verifier(),
		now:          func() time.Time { return now },
		verifyTDX:    func([]byte) error { return nil },
	}
	result, err := verifier.verify(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy != chutesVerificationPolicy || result.ExpiresAt.Sub(result.VerifiedAt) != chutesProofTTL {
		t.Fatalf("unexpected verification result: %#v", result)
	}
}

func TestChutesVerifierAcceptsMissingRedundantInstanceLabel(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	nonce := strings.Repeat("bc", 32)
	e2ePubkey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 1184))
	mrtd := bytes.Repeat([]byte{1}, 48)
	rtmrs := [][]byte{
		bytes.Repeat([]byte{2}, 48), bytes.Repeat([]byte{3}, 48),
		bytes.Repeat([]byte{4}, 48), bytes.Repeat([]byte{5}, 48),
	}
	request, measurement := makeChutesVerificationRequest(t, now, nonce, e2ePubkey, mrtd, rtmrs, false)
	var evidence chutesEvidence
	if err := json.Unmarshal(request.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	evidence.InstanceID = ""
	request.Evidence, _ = json.Marshal(evidence)
	binding := sha256.Sum256([]byte(nonce + e2ePubkey))
	nras := newNRASTestServer(t, now, hex.EncodeToString(binding[:]), true)
	defer nras.server.Close()
	verifier := &chutesVerifier{
		measurements: []chutesMeasurement{*measurement},
		nras:         nras.verifier(),
		now:          func() time.Time { return now },
		verifyTDX:    func([]byte) error { return nil },
	}
	if _, err := verifier.verify(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func TestChutesVerifierRejectsDebugUnpinnedAndOutdatedTDX(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	nonce := strings.Repeat("cd", 32)
	e2ePubkey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 1184))
	mrtd := bytes.Repeat([]byte{1}, 48)
	rtmrs := [][]byte{
		bytes.Repeat([]byte{2}, 48), bytes.Repeat([]byte{3}, 48),
		bytes.Repeat([]byte{4}, 48), bytes.Repeat([]byte{5}, 48),
	}

	t.Run("debug", func(t *testing.T) {
		request, measurement := makeChutesVerificationRequest(t, now, nonce, e2ePubkey, mrtd, rtmrs, true)
		verifier := &chutesVerifier{measurements: []chutesMeasurement{*measurement}, nras: newNRASVerifier(), now: func() time.Time { return now }, verifyTDX: func([]byte) error { return nil }}
		if _, err := verifier.verify(context.Background(), request); err == nil || !strings.Contains(err.Error(), "debug") {
			t.Fatalf("debug quote error = %v", err)
		}
	})

	t.Run("unpinned measurement", func(t *testing.T) {
		request, measurement := makeChutesVerificationRequest(t, now, nonce, e2ePubkey, mrtd, rtmrs, false)
		measurement.MRTD = strings.Repeat("00", 48)
		verifier := &chutesVerifier{measurements: []chutesMeasurement{*measurement}, nras: newNRASVerifier(), now: func() time.Time { return now }, verifyTDX: func([]byte) error { return nil }}
		if _, err := verifier.verify(context.Background(), request); err == nil || !strings.Contains(err.Error(), "not pinned") {
			t.Fatalf("unpinned quote error = %v", err)
		}
	})

	t.Run("outdated collateral", func(t *testing.T) {
		request, measurement := makeChutesVerificationRequest(t, now, nonce, e2ePubkey, mrtd, rtmrs, false)
		verifier := &chutesVerifier{measurements: []chutesMeasurement{*measurement}, nras: newNRASVerifier(), now: func() time.Time { return now }, verifyTDX: func([]byte) error { return fmt.Errorf("TCB Status is not UpToDate") }}
		if _, err := verifier.verify(context.Background(), request); err == nil || !strings.Contains(err.Error(), "UpToDate") {
			t.Fatalf("outdated quote error = %v", err)
		}
	})
}

func TestChutesVerifierRejectsMutatedBindingsAndProofs(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	nonce := strings.Repeat("ac", 32)
	e2ePubkey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 1184))
	mrtd := bytes.Repeat([]byte{1}, 48)
	rtmrs := [][]byte{
		bytes.Repeat([]byte{2}, 48), bytes.Repeat([]byte{3}, 48),
		bytes.Repeat([]byte{4}, 48), bytes.Repeat([]byte{5}, 48),
	}

	for name, mutate := range map[string]func(*chutesVerificationRequest){
		"instance": func(request *chutesVerificationRequest) { request.Instance = "wrong-instance" },
		"nonce":    func(request *chutesVerificationRequest) { request.Nonce = strings.Repeat("ad", 32) },
		"e2e key": func(request *chutesVerificationRequest) {
			request.E2EPubkey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{10}, 1184))
		},
		"signature": func(request *chutesVerificationRequest) {
			var evidence chutesEvidence
			if err := json.Unmarshal(request.Evidence, &evidence); err != nil {
				t.Fatal(err)
			}
			signature, err := base64.StdEncoding.DecodeString(evidence.Signature)
			if err != nil {
				t.Fatal(err)
			}
			signature[0] ^= 0x80
			evidence.Signature = base64.StdEncoding.EncodeToString(signature)
			request.Evidence, _ = json.Marshal(evidence)
		},
	} {
		t.Run(name, func(t *testing.T) {
			request, measurement := makeChutesVerificationRequest(t, now, nonce, e2ePubkey, mrtd, rtmrs, false)
			mutate(request)
			verifier := &chutesVerifier{
				measurements: []chutesMeasurement{*measurement},
				nras:         newNRASVerifier(),
				now:          func() time.Time { return now },
				verifyTDX:    func([]byte) error { return nil },
			}
			if _, err := verifier.verify(context.Background(), request); err == nil {
				t.Fatal("mutated evidence was accepted")
			}
		})
	}
}

func TestNRASVerifierRejectsSignedOverallFailure(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	nonce := strings.Repeat("ef", 32)
	nras := newNRASTestServer(t, now, nonce, false)
	defer nras.server.Close()
	err := nras.verifier().verify(
		context.Background(),
		nonce,
		[]chutesGPUEvidence{{Certificate: "cert", Evidence: "evidence", Arch: "HOPPER"}},
		[]string{"h200"},
	)
	if err == nil || !strings.Contains(err.Error(), "overall attestation result is false") {
		t.Fatalf("NRAS failure error = %v", err)
	}
}

func TestNRASVerifierRejectsInvalidSignedClaims(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	nonce := strings.Repeat("ef", 32)
	tests := map[string]struct {
		mutateOverall  func(map[string]any)
		mutateDetached func(map[string]any)
		expected       string
	}{
		"subject": {
			mutateOverall: func(claims map[string]any) { claims["sub"] = "OTHER" },
			expected:      "subject",
		},
		"overall nonce": {
			mutateOverall: func(claims map[string]any) { claims["eat_nonce"] = "wrong" },
			expected:      "nonce",
		},
		"detached nonce": {
			mutateDetached: func(claims map[string]any) { claims["eat_nonce"] = "wrong" },
			expected:       "nonce",
		},
		"required verdict": {
			mutateDetached: func(claims map[string]any) {
				claims["x-nvidia-gpu-attestation-report-signature-verified"] = false
			},
			expected: "signature-verified",
		},
		"hardware model": {
			mutateDetached: func(claims map[string]any) { claims["hwmodel"] = "NVIDIA L4" },
			expected:       "hardware model",
		},
		"expired": {
			mutateOverall: func(claims map[string]any) { claims["exp"] = now.Add(-time.Second).Unix() },
			expected:      "expired",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			nras := newNRASTestServer(t, now, nonce, true)
			nras.mutateOverall = test.mutateOverall
			nras.mutateDetached = test.mutateDetached
			defer nras.server.Close()
			err := nras.verifier().verify(
				context.Background(),
				nonce,
				[]chutesGPUEvidence{{Certificate: "cert", Evidence: "evidence", Arch: "HOPPER"}},
				[]string{"h200"},
			)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("invalid NRAS claim error = %v, want %q", err, test.expected)
			}
		})
	}
}

func TestPinnedChutesMeasurementsAreWellFormed(t *testing.T) {
	verifier, err := newChutesVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier.measurements) < 20 {
		t.Fatalf("pinned measurements = %d, want current complete snapshot", len(verifier.measurements))
	}
}

func TestMatchesExpectedGPUPreservesExplicitSKUToDieMappings(t *testing.T) {
	for name, test := range map[string]struct {
		actual   string
		expected string
		want     bool
	}{
		"H200 uses GH100 die":          {actual: "GH100 A01 GSP BROM", expected: "h200", want: true},
		"B200 uses GB100 die":          {actual: "GB100", expected: "b200", want: true},
		"RTX Pro 6000 uses GB202 die":  {actual: "GB202", expected: "pro_6000", want: true},
		"B300 uses GB300 die":          {actual: "GB300", expected: "b300", want: true},
		"other Hopper SKU is rejected": {actual: "GH100", expected: "b200", want: false},
		"unlisted die is rejected":     {actual: "GB10B", expected: "pro_6000", want: false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := matchesExpectedGPU(test.actual, []string{test.expected}); got != test.want {
				t.Fatalf("matchesExpectedGPU(%q, %q) = %v, want %v", test.actual, test.expected, got, test.want)
			}
		})
	}
}
