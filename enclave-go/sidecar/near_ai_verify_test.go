package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

type nearAITestCase struct {
	request     *nearAIVerificationRequest
	report      nearAIReport
	verifier    *nearAIVerifier
	policy      nearAIPolicy
	modelBody   *tdxpb.TDQuoteBody
	managerBody *tdxpb.TDQuoteBody
}

func nearAITestMRConfig(composeHash string) []byte {
	compose, _ := hex.DecodeString(composeHash)
	return append(append([]byte{1}, compose...), make([]byte, 15)...)
}

func newNearAITestCase(t *testing.T) *nearAITestCase {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	policy := nearAIPolicy{
		Model:            "z-ai/glm-5.2",
		Domain:           "glm-5-2.completions.near.ai",
		ComposeHash:      strings.Repeat("11", 32),
		DeploymentFile:   "prod/glm-5.2.yaml",
		DeploymentCommit: strings.Repeat("22", 20),
		DeploymentSHA256: strings.Repeat("33", 32),
	}
	nonceHex := strings.Repeat("aa", 32)
	nonce, _ := hex.DecodeString(nonceHex)
	tlsHex := strings.Repeat("bb", 32)
	tlsFingerprint, _ := hex.DecodeString(tlsHex)
	signingKeyHex := strings.Repeat("cc", 32)
	signingKey, _ := hex.DecodeString(signingKeyHex)

	actions, err := json.Marshal([]nearAIDeploymentAction{{
		Timestamp:  "2026-08-24T00:00:00Z",
		Action:     "compose_up",
		Tag:        "v1",
		Commit:     policy.DeploymentCommit,
		File:       policy.DeploymentFile,
		FileSHA256: policy.DeploymentSHA256,
		Services:   []string{"model"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSON(actions)
	if err != nil {
		t.Fatal(err)
	}
	actionsDigest := sha256.Sum256(canonical)
	managerReportData := append(append([]byte{}, actionsDigest[:]...), nonce...)
	modelBinding := sha256.Sum256(append(append([]byte{}, signingKey...), tlsFingerprint...))
	modelReportData := append(append([]byte{}, modelBinding[:]...), nonce...)

	gpus := make([]chutesGPUEvidence, 8)
	for index := range gpus {
		gpus[index] = chutesGPUEvidence{Certificate: "certificate", Evidence: "evidence", Arch: "HOPPER"}
	}
	nvidiaPayload, err := json.Marshal(nearAINVIDIAPayload{
		Nonce: nonceHex, EvidenceList: gpus, Arch: "HOPPER",
	})
	if err != nil {
		t.Fatal(err)
	}

	modelBody := &tdxpb.TDQuoteBody{
		ReportData: modelReportData,
		MrConfigId: nearAITestMRConfig(policy.ComposeHash),
	}
	managerBody := &tdxpb.TDQuoteBody{
		ReportData: managerReportData,
		MrConfigId: nearAITestMRConfig(policy.ComposeHash),
	}
	report := nearAIReport{
		ModelName:        policy.Model,
		RequestNonce:     nonceHex,
		SigningAddress:   signingKeyHex,
		SigningPublicKey: signingKeyHex,
		SigningAlgorithm: "ed25519",
		TLSFingerprint:   tlsHex,
		IntelQuote:       "model-quote",
		NVIDIAPayload:    string(nvidiaPayload),
		ComposeManager: nearAIComposeManagerEvidence{
			Actions: actions, ActionsHash: hex.EncodeToString(actionsDigest[:]),
			Nonce: nonceHex, ReportData: hex.EncodeToString(managerReportData), Quote: "manager-quote",
		},
	}
	report.Info.AppName = nearAIAppName
	report.Info.ComposeHash = policy.ComposeHash
	report.Info.OSImageHash = nearAIOSImageHash

	verifier := &nearAIVerifier{
		policies: map[string]nearAIPolicy{nearAIPolicyKey(policy.Model, policy.Domain): policy},
		now:      func() time.Time { return now },
		verifyQuote: func(encoded string) (*tdxpb.TDQuoteBody, error) {
			switch encoded {
			case "model-quote":
				return modelBody, nil
			case "manager-quote":
				return managerBody, nil
			default:
				return nil, errors.New("unknown quote")
			}
		},
		verifyGPU: func(_ context.Context, gotNonce string, evidence []chutesGPUEvidence, expected []string) error {
			if gotNonce != nonceHex || len(evidence) != 8 || !equalStrings(expected, []string{"H200"}) {
				return errors.New("unexpected GPU verification request")
			}
			return nil
		},
	}
	request := &nearAIVerificationRequest{
		Model: policy.Model, Domain: policy.Domain, Nonce: nonceHex, TLSFingerprint: tlsHex,
	}
	testCase := &nearAITestCase{
		request: request, report: report, verifier: verifier, policy: policy,
		modelBody: modelBody, managerBody: managerBody,
	}
	testCase.encodeReport(t)
	return testCase
}

func (c *nearAITestCase) encodeReport(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(c.report)
	if err != nil {
		t.Fatal(err)
	}
	c.request.Evidence = raw
}

func equalStrings(left, right []string) bool {
	return len(left) == len(right) && strings.Join(left, "\x00") == strings.Join(right, "\x00")
}

func TestNearAIVerifierAcceptsFullyBoundDirectEvidence(t *testing.T) {
	testCase := newNearAITestCase(t)
	result, err := testCase.verifier.verify(context.Background(), testCase.request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy != nearAIVerificationPolicy || result.ExpiresAt.Sub(result.VerifiedAt) != nearAIProofTTL {
		t.Fatalf("unexpected verification result: %#v", result)
	}
}

func TestNearAIVerifierRejectsMutatedBindingsAndDeployment(t *testing.T) {
	tests := map[string]func(*nearAITestCase){
		"unlisted model":         func(c *nearAITestCase) { c.request.Model = "attacker/model" },
		"unlisted domain":        func(c *nearAITestCase) { c.request.Domain = "attacker.completions.near.ai" },
		"report nonce":           func(c *nearAITestCase) { c.report.RequestNonce = strings.Repeat("dd", 32) },
		"report TLS key":         func(c *nearAITestCase) { c.report.TLSFingerprint = strings.Repeat("dd", 32) },
		"signing algorithm":      func(c *nearAITestCase) { c.report.SigningAlgorithm = "ecdsa" },
		"signing key":            func(c *nearAITestCase) { c.report.SigningPublicKey = strings.Repeat("dd", 32) },
		"workload app":           func(c *nearAITestCase) { c.report.Info.AppName = "untrusted" },
		"workload OS":            func(c *nearAITestCase) { c.report.Info.OSImageHash = strings.Repeat("dd", 32) },
		"workload compose":       func(c *nearAITestCase) { c.report.Info.ComposeHash = strings.Repeat("dd", 32) },
		"model quote binding":    func(c *nearAITestCase) { c.modelBody.ReportData[0] ^= 0x80 },
		"model quote workload":   func(c *nearAITestCase) { c.modelBody.MrConfigId[1] ^= 0x80 },
		"manager action hash":    func(c *nearAITestCase) { c.report.ComposeManager.ActionsHash = strings.Repeat("dd", 32) },
		"manager report data":    func(c *nearAITestCase) { c.report.ComposeManager.ReportData = strings.Repeat("dd", 64) },
		"manager quote binding":  func(c *nearAITestCase) { c.managerBody.ReportData[0] ^= 0x80 },
		"manager quote workload": func(c *nearAITestCase) { c.managerBody.MrConfigId[1] ^= 0x80 },
		"deployment commit": func(c *nearAITestCase) {
			var actions []nearAIDeploymentAction
			_ = json.Unmarshal(c.report.ComposeManager.Actions, &actions)
			actions[0].Commit = strings.Repeat("dd", 20)
			c.report.ComposeManager.Actions, _ = json.Marshal(actions)
			canonical, _ := canonicalJSON(c.report.ComposeManager.Actions)
			digest := sha256.Sum256(canonical)
			c.report.ComposeManager.ActionsHash = hex.EncodeToString(digest[:])
			nonce, _ := hex.DecodeString(c.request.Nonce)
			reportData := append(append([]byte{}, digest[:]...), nonce...)
			c.report.ComposeManager.ReportData = hex.EncodeToString(reportData)
			c.managerBody.ReportData = reportData
		},
		"GPU count": func(c *nearAITestCase) {
			var payload nearAINVIDIAPayload
			_ = json.Unmarshal([]byte(c.report.NVIDIAPayload), &payload)
			payload.EvidenceList = payload.EvidenceList[:7]
			raw, _ := json.Marshal(payload)
			c.report.NVIDIAPayload = string(raw)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			testCase := newNearAITestCase(t)
			mutate(testCase)
			testCase.encodeReport(t)
			if _, err := testCase.verifier.verify(context.Background(), testCase.request); err == nil {
				t.Fatal("mutated NEAR AI evidence was accepted")
			}
		})
	}
}

func TestNearAIVerifierRejectsGPUVerifierFailure(t *testing.T) {
	testCase := newNearAITestCase(t)
	testCase.verifier.verifyGPU = func(context.Context, string, []chutesGPUEvidence, []string) error {
		return errors.New("NRAS rejected GPU")
	}
	if _, err := testCase.verifier.verify(context.Background(), testCase.request); err == nil ||
		!strings.Contains(err.Error(), "NRAS rejected GPU") {
		t.Fatalf("GPU verifier error = %v", err)
	}
}

func TestValidateNearAIPoliciesFailsClosed(t *testing.T) {
	valid := newNearAITestCase(t).policy
	if policies, err := validateNearAIPolicies([]nearAIPolicy{valid}); err != nil || len(policies) != 1 {
		t.Fatalf("valid policy rejected: policies=%d err=%v", len(policies), err)
	}
	tests := map[string]func(*nearAIPolicy){
		"domain":         func(p *nearAIPolicy) { p.Domain = "near.ai" },
		"compose hash":   func(p *nearAIPolicy) { p.ComposeHash = strings.Repeat("11", 31) },
		"uppercase hash": func(p *nearAIPolicy) { p.ComposeHash = strings.Repeat("AA", 32) },
		"commit":         func(p *nearAIPolicy) { p.DeploymentCommit = strings.Repeat("22", 19) },
		"file traversal": func(p *nearAIPolicy) { p.DeploymentFile = "../secret" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			entry := valid
			mutate(&entry)
			if _, err := validateNearAIPolicies([]nearAIPolicy{entry}); err == nil {
				t.Fatal("invalid policy was accepted")
			}
		})
	}
	if _, err := validateNearAIPolicies([]nearAIPolicy{valid, valid}); err == nil {
		t.Fatal("duplicate policy was accepted")
	}
}

func TestMatchesNearAIMRConfigRequiresExactDstackLayout(t *testing.T) {
	compose := strings.Repeat("11", 32)
	valid := nearAITestMRConfig(compose)
	if !matchesNearAIMRConfig(valid, compose) {
		t.Fatal("valid MRCONFIG rejected")
	}
	for _, invalid := range [][]byte{
		valid[:47], append([]byte{2}, valid[1:]...), append(append([]byte{}, valid[:47]...), 1),
	} {
		if matchesNearAIMRConfig(invalid, compose) {
			t.Fatalf("invalid MRCONFIG accepted: %x", invalid)
		}
	}
	if bytes.Equal(valid, make([]byte, len(valid))) {
		t.Fatal("test MRCONFIG unexpectedly blank")
	}
}
