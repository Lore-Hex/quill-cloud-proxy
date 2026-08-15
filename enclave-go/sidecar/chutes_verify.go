package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
)

const (
	chutesVerificationPolicy = "chutes-tdx-nvidia-e2e-v1"
	chutesProofTTL           = 2 * time.Minute
	chutesMaxEvidenceBytes   = 16 << 20
	chutesMaxNRASBytes       = 4 << 20
	chutesNRASURL            = "https://nras.attestation.nvidia.com/v3/attest/gpu"
	chutesNRASJWKSURL        = "https://nras.attestation.nvidia.com/.well-known/jwks.json"
)

//go:embed chutes_measurements.json
var chutesMeasurementFS embed.FS

type chutesVerificationRequest struct {
	ChuteID   string          `json:"chute_id"`
	Instance  string          `json:"instance_id"`
	Nonce     string          `json:"nonce"`
	E2EPubkey string          `json:"e2e_pubkey"`
	Evidence  json.RawMessage `json:"evidence"`
}

type chutesVerificationResponse struct {
	VerifiedAt time.Time `json:"verified_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Policy     string    `json:"policy"`
}

type chutesEvidence struct {
	Quote        string          `json:"quote"`
	GPUEvidence  json.RawMessage `json:"gpu_evidence"`
	InstanceID   string          `json:"instance_id"`
	Certificate  string          `json:"certificate"`
	Signature    string          `json:"signature"`
	AttestedBody string          `json:"attested_body"`
}

type signedChutesEvidence struct {
	Nonce    string `json:"nonce"`
	Evidence struct {
		TDXQuote        string `json:"tdx_quote"`
		NVTrustEvidence string `json:"nvtrust_evidence"`
	} `json:"evidence"`
}

type chutesGPUEvidence struct {
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
	Arch        string `json:"arch"`
}

type chutesMeasurement struct {
	Version      string            `json:"version"`
	Name         string            `json:"name"`
	MRTD         string            `json:"mrtd"`
	RuntimeRTMRs map[string]string `json:"runtime_rtmrs"`
	ExpectedGPUs []string          `json:"expected_gpus"`
	GPUCount     int               `json:"gpu_count"`
}

type chutesVerifier struct {
	measurements []chutesMeasurement
	nras         *nrasVerifier
	now          func() time.Time
	verifyTDX    func([]byte) error
}

func newChutesVerifier() (*chutesVerifier, error) {
	raw, err := chutesMeasurementFS.ReadFile("chutes_measurements.json")
	if err != nil {
		return nil, fmt.Errorf("read pinned Chutes measurements: %w", err)
	}
	var measurements []chutesMeasurement
	if err := json.Unmarshal(raw, &measurements); err != nil {
		return nil, fmt.Errorf("decode pinned Chutes measurements: %w", err)
	}
	if err := validateChutesMeasurements(measurements); err != nil {
		return nil, err
	}
	return &chutesVerifier{
		measurements: measurements,
		nras:         newNRASVerifier(),
		now:          time.Now,
		verifyTDX: func(quote []byte) error {
			opts := tdxverify.DefaultOptions()
			opts.GetCollateral = true
			opts.CheckRevocations = true
			return tdxverify.RawTdxQuote(quote, opts)
		},
	}, nil
}

func validateChutesMeasurements(measurements []chutesMeasurement) error {
	if len(measurements) == 0 {
		return errors.New("pinned Chutes measurement list is empty")
	}
	seen := make(map[string]struct{}, len(measurements))
	for _, measurement := range measurements {
		if strings.TrimSpace(measurement.Version) == "" || strings.TrimSpace(measurement.Name) == "" {
			return errors.New("pinned Chutes measurement has no version or name")
		}
		mrtd, err := hex.DecodeString(measurement.MRTD)
		if err != nil || len(mrtd) != 48 {
			return fmt.Errorf("pinned Chutes measurement %q has invalid MRTD", measurement.Name)
		}
		for index := 0; index < 4; index++ {
			value, ok := measurement.RuntimeRTMRs[fmt.Sprintf("RTMR%d", index)]
			decoded, err := hex.DecodeString(value)
			if !ok || err != nil || len(decoded) != 48 {
				return fmt.Errorf("pinned Chutes measurement %q has invalid RTMR%d", measurement.Name, index)
			}
		}
		if measurement.GPUCount < 1 || measurement.GPUCount > 8 || len(measurement.ExpectedGPUs) == 0 {
			return fmt.Errorf("pinned Chutes measurement %q has invalid GPU policy", measurement.Name)
		}
		key := strings.ToUpper(measurement.MRTD)
		for index := 0; index < 4; index++ {
			key += ":" + strings.ToUpper(measurement.RuntimeRTMRs[fmt.Sprintf("RTMR%d", index)])
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (v *chutesVerifier) verify(ctx context.Context, request *chutesVerificationRequest) (*chutesVerificationResponse, error) {
	if request == nil || strings.TrimSpace(request.Instance) == "" ||
		strings.TrimSpace(request.E2EPubkey) == "" || len(request.Evidence) == 0 {
		return nil, errors.New("incomplete Chutes verification request")
	}
	nonceBytes, err := hex.DecodeString(request.Nonce)
	if err != nil || len(nonceBytes) != 32 || strings.ToLower(request.Nonce) != request.Nonce {
		return nil, errors.New("invalid Chutes attestation nonce")
	}
	pubkeyBytes, err := base64.StdEncoding.DecodeString(request.E2EPubkey)
	if err != nil || len(pubkeyBytes) != 1184 {
		return nil, errors.New("invalid Chutes ML-KEM-768 public key")
	}

	var evidence chutesEvidence
	if err := json.Unmarshal(request.Evidence, &evidence); err != nil {
		return nil, fmt.Errorf("decode Chutes evidence: %w", err)
	}
	// Chutes' documented single-instance endpoint currently returns
	// instance_id:null. Accept the missing redundant label, but reject any
	// non-empty mismatch. Identity still fails closed cryptographically below:
	// REPORT_DATA must bind the exact discovered ML-KEM key plus our fresh
	// nonce, so evidence from another instance cannot be substituted.
	if evidence.InstanceID != "" && evidence.InstanceID != request.Instance {
		return nil, errors.New("Chutes evidence instance ID mismatch")
	}
	if evidence.Certificate == "" || evidence.Signature == "" || evidence.AttestedBody == "" {
		return nil, errors.New("Chutes key-possession proof is required")
	}
	certDER, err := base64.StdEncoding.DecodeString(evidence.Certificate)
	if err != nil {
		return nil, errors.New("invalid Chutes evidence certificate encoding")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse Chutes evidence certificate: %w", err)
	}
	now := v.now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, errors.New("Chutes evidence certificate is outside its validity period")
	}
	attestedBody, err := base64.StdEncoding.DecodeString(evidence.AttestedBody)
	if err != nil || len(attestedBody) == 0 || len(attestedBody) > chutesMaxEvidenceBytes {
		return nil, errors.New("invalid signed Chutes evidence body")
	}
	signature, err := base64.StdEncoding.DecodeString(evidence.Signature)
	if err != nil || len(signature) == 0 {
		return nil, errors.New("invalid Chutes evidence signature")
	}
	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Chutes evidence certificate must use an RSA key")
	}
	bodyDigest := sha256.Sum256(attestedBody)
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, bodyDigest[:], signature); err != nil {
		return nil, errors.New("Chutes key-possession signature verification failed")
	}

	var signed signedChutesEvidence
	if err := json.Unmarshal(attestedBody, &signed); err != nil {
		return nil, fmt.Errorf("decode signed Chutes evidence body: %w", err)
	}
	if signed.Nonce != request.Nonce {
		return nil, errors.New("signed Chutes evidence nonce mismatch")
	}
	quote, err := base64.StdEncoding.DecodeString(signed.Evidence.TDXQuote)
	if err != nil || len(quote) == 0 {
		return nil, errors.New("invalid signed Intel TDX quote")
	}
	if err := v.verifyTDX(quote); err != nil {
		return nil, fmt.Errorf("Intel TDX verification failed: %w", err)
	}
	parsed, err := abi.QuoteToProto(quote)
	if err != nil {
		return nil, fmt.Errorf("parse verified Intel TDX quote: %w", err)
	}
	quoteV4, ok := parsed.(*tdxpb.QuoteV4)
	if !ok || quoteV4.GetTdQuoteBody() == nil {
		return nil, errors.New("verified Intel quote is not TDX QuoteV4")
	}
	quoteBody := quoteV4.GetTdQuoteBody()
	if len(quoteBody.GetTdAttributes()) != 8 || quoteBody.GetTdAttributes()[0]&1 != 0 {
		return nil, errors.New("Chutes TDX workload has debug mode enabled or invalid attributes")
	}
	if len(quoteBody.GetReportData()) != 64 {
		return nil, errors.New("Chutes TDX report data has invalid length")
	}
	expectedBinding := sha256.Sum256([]byte(request.Nonce + request.E2EPubkey))
	if !bytes.Equal(quoteBody.GetReportData()[:32], expectedBinding[:]) {
		return nil, errors.New("Chutes TDX quote does not bind the requested nonce and E2E key")
	}
	certKeyDigest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if !bytes.Equal(quoteBody.GetReportData()[32:], certKeyDigest[:]) {
		return nil, errors.New("Chutes TDX quote does not bind the response signing key")
	}
	measurement, err := v.matchMeasurement(quoteBody)
	if err != nil {
		return nil, err
	}

	var gpuEvidence []chutesGPUEvidence
	if err := json.Unmarshal([]byte(signed.Evidence.NVTrustEvidence), &gpuEvidence); err != nil {
		return nil, fmt.Errorf("decode signed NVIDIA evidence: %w", err)
	}
	if len(gpuEvidence) != measurement.GPUCount {
		return nil, fmt.Errorf("NVIDIA evidence count %d does not match pinned policy %d", len(gpuEvidence), measurement.GPUCount)
	}
	if err := v.nras.verify(ctx, hex.EncodeToString(expectedBinding[:]), gpuEvidence, measurement.ExpectedGPUs); err != nil {
		return nil, err
	}

	verifiedAt := v.now().UTC()
	return &chutesVerificationResponse{
		VerifiedAt: verifiedAt,
		ExpiresAt:  verifiedAt.Add(chutesProofTTL),
		Policy:     chutesVerificationPolicy,
	}, nil
}

func (v *chutesVerifier) matchMeasurement(body *tdxpb.TDQuoteBody) (*chutesMeasurement, error) {
	if body == nil || len(body.GetMrTd()) != 48 || len(body.GetRtmrs()) != 4 {
		return nil, errors.New("verified Chutes TDX quote has incomplete measurements")
	}
	mrtd := strings.ToUpper(hex.EncodeToString(body.GetMrTd()))
	for index := range v.measurements {
		measurement := &v.measurements[index]
		if strings.ToUpper(measurement.MRTD) != mrtd {
			continue
		}
		matched := true
		for rtmrIndex, actual := range body.GetRtmrs() {
			expected := measurement.RuntimeRTMRs[fmt.Sprintf("RTMR%d", rtmrIndex)]
			if !strings.EqualFold(expected, hex.EncodeToString(actual)) {
				matched = false
				break
			}
		}
		if matched {
			return measurement, nil
		}
	}
	return nil, errors.New("Chutes TDX workload measurement is not pinned in this TrustedRouter release")
}

type nrasVerifier struct {
	client   *http.Client
	endpoint string
	jwksURL  string
	now      func() time.Time

	mu          sync.Mutex
	jwks        map[string]*x509.Certificate
	jwksExpires time.Time
}

func newNRASVerifier() *nrasVerifier {
	return &nrasVerifier{
		client:   &http.Client{Timeout: 45 * time.Second},
		endpoint: chutesNRASURL,
		jwksURL:  chutesNRASJWKSURL,
		now:      time.Now,
		jwks:     make(map[string]*x509.Certificate),
	}
}

func (v *nrasVerifier) verify(
	ctx context.Context,
	nonce string,
	evidence []chutesGPUEvidence,
	expectedModels []string,
) error {
	if len(evidence) == 0 {
		return errors.New("NVIDIA GPU evidence is empty")
	}
	arch := strings.TrimSpace(evidence[0].Arch)
	if arch == "" {
		return errors.New("NVIDIA GPU evidence has no architecture")
	}
	type nrasEvidence struct {
		Evidence    string `json:"evidence"`
		Certificate string `json:"certificate"`
	}
	payload := struct {
		Nonce         string         `json:"nonce"`
		EvidenceList  []nrasEvidence `json:"evidence_list"`
		Arch          string         `json:"arch"`
		ClaimsVersion string         `json:"claims_version"`
	}{Nonce: nonce, Arch: arch, ClaimsVersion: "2.0"}
	for index, item := range evidence {
		if item.Arch != arch || item.Evidence == "" || item.Certificate == "" {
			return fmt.Errorf("NVIDIA GPU evidence %d is incomplete or has inconsistent architecture", index)
		}
		payload.EvidenceList = append(payload.EvidenceList, nrasEvidence{
			Evidence: item.Evidence, Certificate: item.Certificate,
		})
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal NVIDIA NRAS request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TrustedRouter-Attestation/1.0")
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("NVIDIA NRAS request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("NVIDIA NRAS refused GPU evidence with HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, chutesMaxNRASBytes+1))
	if err != nil {
		return fmt.Errorf("read NVIDIA NRAS response: %w", err)
	}
	if len(raw) > chutesMaxNRASBytes {
		return errors.New("NVIDIA NRAS response exceeded size limit")
	}
	return v.verifyEAT(raw, nonce, len(evidence), expectedModels)
}

func (v *nrasVerifier) verifyEAT(raw []byte, nonce string, gpuCount int, expectedModels []string) error {
	var eat []json.RawMessage
	if err := json.Unmarshal(raw, &eat); err != nil || len(eat) != 2 {
		return errors.New("NVIDIA NRAS returned an invalid EAT envelope")
	}
	var overallPair []json.RawMessage
	if err := json.Unmarshal(eat[0], &overallPair); err != nil || len(overallPair) != 2 {
		return errors.New("NVIDIA NRAS returned an invalid overall token")
	}
	var tokenType, overallToken string
	if json.Unmarshal(overallPair[0], &tokenType) != nil || json.Unmarshal(overallPair[1], &overallToken) != nil || tokenType != "JWT" {
		return errors.New("NVIDIA NRAS overall token is not JWT")
	}
	overallClaims, err := v.verifyJWT(overallToken, true)
	if err != nil {
		return fmt.Errorf("verify NVIDIA overall token: %w", err)
	}
	if claimString(overallClaims["sub"]) != "NVIDIA-PLATFORM-ATTESTATION" {
		return errors.New("NVIDIA overall token has an unexpected subject")
	}
	if !claimTrue(overallClaims["x-nvidia-overall-att-result"]) {
		return errors.New("NVIDIA overall attestation result is false")
	}
	if claimString(overallClaims["eat_nonce"]) != nonce {
		return errors.New("NVIDIA overall attestation nonce mismatch")
	}

	var detached map[string]string
	if err := json.Unmarshal(eat[1], &detached); err != nil || len(detached) != gpuCount {
		return fmt.Errorf("NVIDIA detached GPU token count does not match evidence count %d", gpuCount)
	}
	keys := make([]string, 0, len(detached))
	for key := range detached {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		claims, err := v.verifyJWT(detached[key], true)
		if err != nil {
			return fmt.Errorf("verify NVIDIA detached token %s: %w", key, err)
		}
		if claimString(claims["eat_nonce"]) != nonce {
			return fmt.Errorf("NVIDIA detached token %s nonce mismatch", key)
		}
		if !strings.EqualFold(claimString(claims["measres"]), "success") ||
			!claimTrue(claims["secboot"]) || !strings.EqualFold(claimString(claims["dbgstat"]), "disabled") {
			return fmt.Errorf("NVIDIA detached token %s failed secure-boot or measurement policy", key)
		}
		for _, required := range []string{
			"x-nvidia-gpu-arch-check",
			"x-nvidia-gpu-attestation-report-cert-chain-validated",
			"x-nvidia-gpu-attestation-report-parsed",
			"x-nvidia-gpu-attestation-report-nonce-match",
			"x-nvidia-gpu-attestation-report-signature-verified",
		} {
			if !claimTrue(claims[required]) {
				return fmt.Errorf("NVIDIA detached token %s failed %s", key, required)
			}
		}
		if warning := strings.TrimSpace(claimString(claims["x-nvidia-attestation-warning"])); warning != "" {
			return fmt.Errorf("NVIDIA detached token %s contains an attestation warning", key)
		}
		if err := rejectFalseNVIDIAClaims(claims); err != nil {
			return fmt.Errorf("NVIDIA detached token %s: %w", key, err)
		}
		actualModel := claimString(claims["hwmodel"])
		if !matchesExpectedGPU(actualModel, expectedModels) {
			return fmt.Errorf(
				"NVIDIA detached token %s hardware model %q is outside pinned policy %q",
				key,
				truncate(actualModel, 80),
				expectedModels,
			)
		}
	}
	return nil
}

func (v *nrasVerifier) verifyJWT(token string, allowRefresh bool) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("JWT has invalid compact serialization")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("JWT header is not base64url")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if json.Unmarshal(headerRaw, &header) != nil || header.Algorithm != "ES384" || header.KeyID == "" {
		return nil, errors.New("JWT must use ES384 with a key ID")
	}
	cert, err := v.getJWKCertificate(header.KeyID, allowRefresh)
	if err != nil {
		return nil, err
	}
	ecdsaKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || ecdsaKey.Curve.Params().Name != "P-384" {
		return nil, errors.New("NVIDIA JWT key is not ECDSA P-384")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 96 {
		return nil, errors.New("NVIDIA JWT has invalid ES384 signature encoding")
	}
	digest := sha512.Sum384([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(ecdsaKey, digest[:], newBigInt(signature[:48]), newBigInt(signature[48:])) {
		return nil, errors.New("NVIDIA JWT signature verification failed")
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("NVIDIA JWT payload is not base64url")
	}
	decoder := json.NewDecoder(bytes.NewReader(payloadRaw))
	decoder.UseNumber()
	var claims map[string]any
	if err := decoder.Decode(&claims); err != nil {
		return nil, errors.New("NVIDIA JWT payload is invalid JSON")
	}
	if err := validateJWTTimes(claims, v.now()); err != nil {
		return nil, err
	}
	return claims, nil
}

func newBigInt(raw []byte) *big.Int {
	return new(big.Int).SetBytes(raw)
}

type nrasJWKSet struct {
	Keys []struct {
		KeyID string   `json:"kid"`
		X5C   []string `json:"x5c"`
	} `json:"keys"`
}

func (v *nrasVerifier) getJWKCertificate(keyID string, allowRefresh bool) (*x509.Certificate, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.now().Before(v.jwksExpires) {
		if cert := v.jwks[keyID]; cert != nil {
			return cert, nil
		}
	}
	if !allowRefresh {
		return nil, errors.New("NVIDIA JWT key ID is unknown")
	}
	req, err := http.NewRequest(http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "TrustedRouter-Attestation/1.0")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch NVIDIA JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch NVIDIA JWKS: HTTP %d", resp.StatusCode)
	}
	var set nrasJWKSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("decode NVIDIA JWKS: %w", err)
	}
	parsed := make(map[string]*x509.Certificate, len(set.Keys))
	for _, key := range set.Keys {
		if key.KeyID == "" || len(key.X5C) == 0 {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(key.X5C[0])
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil || v.now().Before(cert.NotBefore) || v.now().After(cert.NotAfter) {
			continue
		}
		parsed[key.KeyID] = cert
	}
	if len(parsed) == 0 {
		return nil, errors.New("NVIDIA JWKS contains no usable certificates")
	}
	v.jwks = parsed
	v.jwksExpires = v.now().Add(time.Hour)
	cert := parsed[keyID]
	if cert == nil {
		return nil, errors.New("NVIDIA JWT key ID is absent from JWKS")
	}
	return cert, nil
}

func validateJWTTimes(claims map[string]any, now time.Time) error {
	expires, ok := numericDate(claims["exp"])
	if !ok || !expires.After(now) {
		return errors.New("NVIDIA JWT is expired or has no expiry")
	}
	if notBefore, ok := numericDate(claims["nbf"]); ok && notBefore.After(now.Add(2*time.Minute)) {
		return errors.New("NVIDIA JWT is not yet valid")
	}
	if issuedAt, ok := numericDate(claims["iat"]); ok {
		if issuedAt.After(now.Add(2*time.Minute)) || issuedAt.Before(now.Add(-2*time.Hour)) {
			return errors.New("NVIDIA JWT issue time is outside the accepted window")
		}
	}
	return nil
}

func numericDate(value any) (time.Time, bool) {
	var seconds int64
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseInt(string(typed), 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		seconds = parsed
	case float64:
		seconds = int64(typed)
	default:
		return time.Time{}, false
	}
	return time.Unix(seconds, 0), true
}

func claimString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

func claimTrue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return err == nil && parsed
	default:
		return false
	}
}

func rejectFalseNVIDIAClaims(claims map[string]any) error {
	for key, value := range claims {
		if strings.HasPrefix(key, "x-nvidia-") {
			if boolean, ok := value.(bool); ok && !boolean {
				return fmt.Errorf("claim %s is false", key)
			}
		}
	}
	return nil
}

func matchesExpectedGPU(actual string, expected []string) bool {
	normalizedActual := strings.NewReplacer("nvidia", "", " ", "", "-", "", "_", "").Replace(strings.ToLower(actual))
	for _, model := range expected {
		normalizedExpected := strings.NewReplacer("nvidia", "", " ", "", "-", "", "_", "").Replace(strings.ToLower(model))
		aliases := []string{normalizedExpected}
		// NVIDIA's signed hwmodel claim identifies the GPU die, while
		// Chutes' pinned measurement names identify the product SKU. Keep
		// this translation explicit: accepting a whole architecture family
		// would let a different, weaker SKU satisfy the policy accidentally.
		switch normalizedExpected {
		case "h200":
			aliases = append(aliases, "gh100")
		case "b200":
			aliases = append(aliases, "gb100")
		case "pro6000":
			aliases = append(aliases, "gb202")
		case "b300":
			aliases = append(aliases, "gb300")
		}
		for _, alias := range aliases {
			if alias != "" && strings.Contains(normalizedActual, alias) {
				return true
			}
		}
	}
	return false
}
