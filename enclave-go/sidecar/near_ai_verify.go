package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
)

const (
	nearAIVerificationPolicy = "near-ai-tdx-nvidia-direct-v1"
	nearAIProofTTL           = 2 * time.Minute
	nearAIMaxEvidenceBytes   = 8 << 20
	nearAIAppName            = "dstack-nvidia-0.5.5"
	nearAIOSImageHash        = "9b69bb1698bacbb6985409a2c272bcb892e09cdcea63d5399c6768b67d3ff677"
)

//go:embed near_ai_policy.json
var nearAIPolicyFS embed.FS

type nearAIVerificationRequest struct {
	Model          string          `json:"model"`
	Domain         string          `json:"domain"`
	Nonce          string          `json:"nonce"`
	TLSFingerprint string          `json:"tls_fingerprint"`
	Evidence       json.RawMessage `json:"evidence"`
}

type nearAIVerificationResponse struct {
	VerifiedAt time.Time `json:"verified_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Policy     string    `json:"policy"`
}

type nearAIPolicy struct {
	Model            string `json:"model"`
	Domain           string `json:"domain"`
	ComposeHash      string `json:"compose_hash"`
	DeploymentFile   string `json:"deployment_file"`
	DeploymentCommit string `json:"deployment_commit"`
	DeploymentSHA256 string `json:"deployment_sha256"`
}

type nearAIReport struct {
	ModelName        string `json:"model_name"`
	RequestNonce     string `json:"request_nonce"`
	SigningAddress   string `json:"signing_address"`
	SigningPublicKey string `json:"signing_public_key"`
	SigningAlgorithm string `json:"signing_algo"`
	TLSFingerprint   string `json:"tls_cert_fingerprint"`
	IntelQuote       string `json:"intel_quote"`
	NVIDIAPayload    string `json:"nvidia_payload"`
	Info             struct {
		AppName     string `json:"app_name"`
		ComposeHash string `json:"compose_hash"`
		OSImageHash string `json:"os_image_hash"`
	} `json:"info"`
	ComposeManager nearAIComposeManagerEvidence `json:"compose_manager_attestation"`
}

type nearAIComposeManagerEvidence struct {
	Actions     json.RawMessage `json:"actions"`
	ActionsHash string          `json:"actions_hash"`
	Nonce       string          `json:"nonce"`
	ReportData  string          `json:"report_data"`
	Quote       string          `json:"quote"`
}

type nearAIDeploymentAction struct {
	Timestamp  string   `json:"timestamp"`
	Action     string   `json:"action"`
	Tag        string   `json:"tag"`
	Commit     string   `json:"commit"`
	File       string   `json:"file"`
	FileSHA256 string   `json:"file_sha256"`
	Services   []string `json:"services"`
}

type nearAINVIDIAPayload struct {
	Nonce        string              `json:"nonce"`
	EvidenceList []chutesGPUEvidence `json:"evidence_list"`
	Arch         string              `json:"arch"`
}

type nearAIVerifier struct {
	policies    map[string]nearAIPolicy
	nras        *nrasVerifier
	now         func() time.Time
	verifyQuote func(string) (*tdxpb.TDQuoteBody, error)
	verifyGPU   func(context.Context, string, []chutesGPUEvidence, []string) error
}

func newNearAIVerifier() (*nearAIVerifier, error) {
	raw, err := nearAIPolicyFS.ReadFile("near_ai_policy.json")
	if err != nil {
		return nil, fmt.Errorf("read pinned NEAR AI policy: %w", err)
	}
	var entries []nearAIPolicy
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("decode pinned NEAR AI policy: %w", err)
	}
	policies, err := validateNearAIPolicies(entries)
	if err != nil {
		return nil, err
	}
	nras := newNRASVerifier()
	return &nearAIVerifier{
		policies: policies,
		nras:     nras,
		now:      time.Now,
		verifyQuote: func(encoded string) (*tdxpb.TDQuoteBody, error) {
			quote, err := hex.DecodeString(encoded)
			if err != nil || len(quote) == 0 {
				return nil, errors.New("invalid Intel TDX quote encoding")
			}
			opts := tdxverify.DefaultOptions()
			opts.GetCollateral = true
			opts.CheckRevocations = true
			return verifyTDXQuote(quote, func(raw []byte) error {
				return tdxverify.RawTdxQuote(raw, opts)
			})
		},
		verifyGPU: nras.verify,
	}, nil
}

func nearAIPolicyKey(model, domain string) string {
	return model + "\x00" + strings.ToLower(domain)
}

func validateNearAIPolicies(entries []nearAIPolicy) (map[string]nearAIPolicy, error) {
	if len(entries) == 0 {
		return nil, errors.New("pinned NEAR AI policy is empty")
	}
	policies := make(map[string]nearAIPolicy, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.Model) == "" || strings.TrimSpace(entry.Domain) == "" ||
			!strings.HasSuffix(strings.ToLower(entry.Domain), ".completions.near.ai") ||
			strings.ContainsAny(entry.Domain, "/:@") {
			return nil, fmt.Errorf("pinned NEAR AI policy has invalid model or domain %q", entry.Domain)
		}
		for _, field := range []struct {
			label string
			value string
			bytes int
		}{
			{label: "compose hash", value: entry.ComposeHash, bytes: 32},
			{label: "deployment commit", value: entry.DeploymentCommit, bytes: 20},
			{label: "deployment sha256", value: entry.DeploymentSHA256, bytes: 32},
		} {
			decoded, err := hex.DecodeString(field.value)
			if err != nil || len(decoded) != field.bytes || field.value != strings.ToLower(field.value) {
				return nil, fmt.Errorf("pinned NEAR AI %s is invalid for %s", field.label, entry.Model)
			}
		}
		if strings.TrimSpace(entry.DeploymentFile) == "" || strings.HasPrefix(entry.DeploymentFile, "/") ||
			strings.Contains(entry.DeploymentFile, "..") {
			return nil, fmt.Errorf("pinned NEAR AI deployment file is invalid for %s", entry.Model)
		}
		key := nearAIPolicyKey(entry.Model, entry.Domain)
		if _, exists := policies[key]; exists {
			return nil, fmt.Errorf("duplicate NEAR AI policy for %s", entry.Model)
		}
		policies[key] = entry
	}
	return policies, nil
}

func (v *nearAIVerifier) verify(ctx context.Context, request *nearAIVerificationRequest) (*nearAIVerificationResponse, error) {
	if request == nil || len(request.Evidence) == 0 {
		return nil, errors.New("incomplete NEAR AI verification request")
	}
	policy, ok := v.policies[nearAIPolicyKey(request.Model, request.Domain)]
	if !ok {
		return nil, errors.New("NEAR AI model and direct domain are not pinned in this TrustedRouter release")
	}
	nonce, err := strictHex32(request.Nonce, "NEAR AI nonce")
	if err != nil {
		return nil, err
	}
	tlsFingerprint, err := strictHex32(request.TLSFingerprint, "NEAR AI TLS fingerprint")
	if err != nil {
		return nil, err
	}

	var report nearAIReport
	if err := json.Unmarshal(request.Evidence, &report); err != nil {
		return nil, fmt.Errorf("decode NEAR AI attestation report: %w", err)
	}
	if report.ModelName != policy.Model || report.RequestNonce != request.Nonce ||
		!strings.EqualFold(report.TLSFingerprint, request.TLSFingerprint) {
		return nil, errors.New("NEAR AI report model, nonce, or TLS fingerprint mismatch")
	}
	if report.SigningAlgorithm != "ed25519" || report.SigningAddress != report.SigningPublicKey {
		return nil, errors.New("NEAR AI report must use one matching Ed25519 signing key")
	}
	signingKey, err := strictHex32(report.SigningAddress, "NEAR AI signing key")
	if err != nil {
		return nil, err
	}
	if report.Info.AppName != nearAIAppName || report.Info.OSImageHash != nearAIOSImageHash ||
		report.Info.ComposeHash != policy.ComposeHash {
		return nil, errors.New("NEAR AI workload identity is outside the pinned policy")
	}

	topBody, err := v.verifyQuote(report.IntelQuote)
	if err != nil {
		return nil, fmt.Errorf("NEAR AI model quote: %w", err)
	}
	expectedBinding := sha256.Sum256(append(append([]byte{}, signingKey...), tlsFingerprint...))
	if len(topBody.GetReportData()) != 64 || !bytes.Equal(topBody.GetReportData()[:32], expectedBinding[:]) ||
		!bytes.Equal(topBody.GetReportData()[32:], nonce) {
		return nil, errors.New("NEAR AI model quote does not bind the signing key, live TLS key, and nonce")
	}
	if !matchesNearAIMRConfig(topBody.GetMrConfigId(), policy.ComposeHash) {
		return nil, errors.New("NEAR AI model quote does not bind the pinned workload compose hash")
	}

	if err := v.verifyComposeManager(report.ComposeManager, request.Nonce, nonce, policy); err != nil {
		return nil, err
	}
	if err := v.verifyNVIDIA(ctx, report.NVIDIAPayload, request.Nonce); err != nil {
		return nil, err
	}

	verifiedAt := v.now().UTC()
	return &nearAIVerificationResponse{
		VerifiedAt: verifiedAt,
		ExpiresAt:  verifiedAt.Add(nearAIProofTTL),
		Policy:     nearAIVerificationPolicy,
	}, nil
}

func (v *nearAIVerifier) verifyComposeManager(
	evidence nearAIComposeManagerEvidence,
	nonceHex string,
	nonce []byte,
	policy nearAIPolicy,
) error {
	if evidence.Nonce != nonceHex || len(evidence.Actions) == 0 {
		return errors.New("NEAR AI compose-manager evidence is incomplete or has a nonce mismatch")
	}
	canonical, err := canonicalJSON(evidence.Actions)
	if err != nil {
		return fmt.Errorf("canonicalize NEAR AI deployment actions: %w", err)
	}
	actionsDigest := sha256.Sum256(canonical)
	if !strings.EqualFold(hex.EncodeToString(actionsDigest[:]), evidence.ActionsHash) {
		return errors.New("NEAR AI deployment action log hash mismatch")
	}
	reportData, err := hex.DecodeString(evidence.ReportData)
	if err != nil || len(reportData) != 64 || !bytes.Equal(reportData[:32], actionsDigest[:]) ||
		!bytes.Equal(reportData[32:], nonce) {
		return errors.New("NEAR AI compose-manager report data mismatch")
	}
	body, err := v.verifyQuote(evidence.Quote)
	if err != nil {
		return fmt.Errorf("NEAR AI compose-manager quote: %w", err)
	}
	if !bytes.Equal(body.GetReportData(), reportData) || !matchesNearAIMRConfig(body.GetMrConfigId(), policy.ComposeHash) {
		return errors.New("NEAR AI compose-manager quote does not bind the action log, nonce, and workload")
	}

	var actions []nearAIDeploymentAction
	if err := json.Unmarshal(evidence.Actions, &actions); err != nil {
		return fmt.Errorf("decode NEAR AI deployment actions: %w", err)
	}
	var latest *nearAIDeploymentAction
	for index := range actions {
		if actions[index].File == policy.DeploymentFile {
			latest = &actions[index]
		}
	}
	if latest == nil || latest.Action != "compose_up" || latest.Commit != policy.DeploymentCommit ||
		latest.FileSHA256 != policy.DeploymentSHA256 {
		return errors.New("NEAR AI active deployment is not pinned in this TrustedRouter release")
	}
	return nil
}

func (v *nearAIVerifier) verifyNVIDIA(ctx context.Context, encoded, nonce string) error {
	var payload nearAINVIDIAPayload
	if err := json.Unmarshal([]byte(encoded), &payload); err != nil {
		return fmt.Errorf("decode NEAR AI NVIDIA evidence: %w", err)
	}
	if payload.Nonce != nonce || payload.Arch != "HOPPER" || len(payload.EvidenceList) != 8 {
		return errors.New("NEAR AI NVIDIA evidence has the wrong nonce, architecture, or GPU count")
	}
	for index := range payload.EvidenceList {
		payload.EvidenceList[index].Arch = payload.Arch
	}
	if err := v.verifyGPU(ctx, nonce, payload.EvidenceList, []string{"H200"}); err != nil {
		return fmt.Errorf("NEAR AI NVIDIA verification failed: %w", err)
	}
	return nil
}

func strictHex32(value, label string) ([]byte, error) {
	if value != strings.ToLower(value) {
		return nil, fmt.Errorf("%s must be lowercase hexadecimal", label)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("%s must contain exactly 32 bytes", label)
	}
	return decoded, nil
}

func matchesNearAIMRConfig(actual []byte, composeHash string) bool {
	compose, err := hex.DecodeString(composeHash)
	if err != nil || len(actual) != 48 || len(compose) != 32 || actual[0] != 1 {
		return false
	}
	if !bytes.Equal(actual[1:33], compose) {
		return false
	}
	return bytes.Equal(actual[33:], make([]byte, 15))
}

func canonicalJSON(raw json.RawMessage) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}
