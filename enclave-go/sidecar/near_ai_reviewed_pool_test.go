package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

// Public history captured with fresh nonces on November 12, 2026 (dstack
// 0.5.12 guest). These tests exercise policy binding; cryptographic validation
// is covered by TestLiveNearAIEvidence, not by the quote/GPU doubles used here.
const (
	nearAIGPU03Compose = "c900dc7304663b73b623cd5d941fbdab6f02858017b371ae28de445a16d2e2d0"
	// Retired: gpu03 before its November 12 base-manifest change, and gpu04,
	// which no longer serves the pool.
	nearAIRetiredNov6GPU03Compose = "a0e3c6f4f21a60ea3f5c96bc7ef319b03a184ca2049605399275fbcea74e8c5f"
	nearAIRetiredNov6GPU04Compose = "5f7ebd85cf1f480a118f75dd10fd0cb277e4ddbb23845f1c20d8ea0f1e87efa6"
	// Retired: the same two instances before their dstack 0.5.12 reboot.
	nearAIRetiredGPU03Compose = "55db164f4f8c6a837c2217c601c21bba4758f908536a6cd5b2978550205a9179"
	nearAIRetiredGPU04Compose = "c82b1a2eaf6996154a5f39ae621643f034b082d5e51edd3d2ba6009273881d86"
	// Unreviewed: a shared small-models CVM (instance a8a25faa) that NEAR
	// added to the same DNS name. It must keep failing closed.
	nearAIUnreviewedSmallModelsCompose = "e8416a02d6f7ce47baaa52e3925b934fd30834b04fc9086b363db9b1d12c729d"
)

func reviewedNearAIPoolCase(t *testing.T, compose string) *nearAITestCase {
	t.Helper()
	c := newNearAITestCase(t)
	v, err := newNearAIVerifier()
	if err != nil {
		t.Fatal(err)
	}
	const model = "z-ai/glm-5.3-flash"
	const domain = "glm-5-3-flash.completions.near.ai"
	entries := v.policies[nearAIPolicyKey(model, domain)]
	if len(entries) != 1 {
		t.Fatalf("want exactly one reviewed GLM pool member, got %d", len(entries))
	}
	var policy nearAIPolicy
	for _, entry := range entries {
		if entry.ComposeHash == compose {
			policy = entry
		}
	}
	if policy.Model == "" || policy.BootMeasurements == nil || policy.DeploymentActionsSHA256 == "" {
		t.Fatal("missing reviewed workload, boot or history pin")
	}
	c.policy = policy
	c.verifier.policies = v.policies
	c.request.Model, c.request.Domain = model, domain
	c.report.ModelName = model
	c.report.Info.AppName = policy.AppName
	c.report.Info.OSImageHash = policy.OSImageHash
	c.report.Info.ComposeHash = compose
	const fixtureDate = "near-ai-2026-11-12"
	eventBytes, err := os.ReadFile(filepath.Join("testdata", fixtureDate, compose[:8]+"-events.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(eventBytes, &c.report.EventLog); err != nil {
		t.Fatal(err)
	}
	rtmr3, err := replayNearAIRuntimeEvents(c.report.EventLog, compose, policy.OSImageHash)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []*tdxpb.TDQuoteBody{c.modelBody, c.managerBody} {
		body.MrConfigId = nearAITestMRConfig(compose)
		body.MrTd, _ = hex.DecodeString(policy.BootMeasurements.MRTD)
		body.Rtmrs[0], _ = hex.DecodeString(policy.BootMeasurements.RTMR0)
		body.Rtmrs[1], _ = hex.DecodeString(policy.BootMeasurements.RTMR1)
		body.Rtmrs[2], _ = hex.DecodeString(policy.BootMeasurements.RTMR2)
		body.Rtmrs[3] = append([]byte{}, rtmr3...)
	}
	actions, err := os.ReadFile(filepath.Join("testdata", fixtureDate, compose[:8]+"-actions.json"))
	if err != nil {
		t.Fatal(err)
	}
	bindNearAITestActions(t, c, actions)
	return c
}

func bindNearAITestActions(t *testing.T, c *nearAITestCase, actions json.RawMessage) {
	t.Helper()
	canonical, err := canonicalJSON(actions)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	c.report.ComposeManager.Actions = actions
	c.report.ComposeManager.ActionsHash = hex.EncodeToString(digest[:])
	nonce, _ := hex.DecodeString(c.request.Nonce)
	c.managerBody.ReportData = append(append([]byte{}, digest[:]...), nonce...)
	c.report.ComposeManager.ReportData = hex.EncodeToString(c.managerBody.ReportData)
	c.encodeReport(t)
}

func TestNearAIReviewedPoolHistories(t *testing.T) {
	compose := nearAIGPU03Compose
	c := reviewedNearAIPoolCase(t, compose)
	if _, err := c.verifier.verify(context.Background(), c.request); err != nil {
		t.Fatalf("reviewed pool member rejected: %v", err)
	}
	for _, stage := range []string{"model", "manager"} {
		t.Run("binds complete event log/"+stage, func(t *testing.T) {
			changed := reviewedNearAIPoolCase(t, compose)
			body := changed.modelBody
			if stage == "manager" {
				body = changed.managerBody
			}
			body.Rtmrs[3][0] ^= 1
			if _, err := changed.verifier.verify(context.Background(), changed.request); err == nil {
				t.Fatal("accepted runtime events not bound by both quotes")
			}
		})
	}

	for name, fixture := range map[string]string{
		// The 226-entry history reviewed on November 6 for this instance.
		"superseded": filepath.Join("near-ai-2026-11-06", "a0e3c6f4-actions.json"),
		// The retired gpu04 history must never satisfy the gpu03 pin.
		"cross-host": filepath.Join("near-ai-2026-11-06", "5f7ebd85-actions.json"),
		"october":    filepath.Join("near-ai-2026-10-09", "55db164f-actions.json"),
	} {
		t.Run(name, func(t *testing.T) {
			c := reviewedNearAIPoolCase(t, compose)
			oldActions, err := os.ReadFile(filepath.Join("testdata", fixture))
			if err != nil {
				t.Fatal(err)
			}
			bindNearAITestActions(t, c, oldActions)
			if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "deployment history") {
				t.Fatalf("accepted %s deployment history: %v", name, err)
			}
		})
	}

	c = reviewedNearAIPoolCase(t, compose)
	var actions []map[string]any
	if err := json.Unmarshal(c.report.ComposeManager.Actions, &actions); err != nil {
		t.Fatal(err)
	}
	// Even a correctly re-quoted telemetry-only update requires review.
	actions = append(actions, map[string]any{
		"action": "compose_up", "timestamp": "2026-11-12T12:00:00Z",
		"file": c.policy.DeploymentFile, "commit": c.policy.DeploymentCommit,
		"file_sha256": c.policy.DeploymentSHA256, "services": []string{"otelcol-contrib"},
	})
	raw, err := json.Marshal(actions)
	if err != nil {
		t.Fatal(err)
	}
	bindNearAITestActions(t, c, raw)
	if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "deployment history") {
		t.Fatalf("unreviewed partial deployment accepted: %v", err)
	}
}

func TestNearAIReviewedPoolRetiresOldCompose(t *testing.T) {
	for _, retired := range []string{
		nearAIRetiredNov6GPU03Compose,
		nearAIRetiredNov6GPU04Compose,
		nearAIRetiredGPU03Compose,
		nearAIRetiredGPU04Compose,
		nearAIUnreviewedSmallModelsCompose,
		"533e43fd215d56ec6cd719adb5defe6615f7ba6ae0b018e832f7c8dadf2e25d4",
	} {
		c := reviewedNearAIPoolCase(t, nearAIGPU03Compose)
		c.report.Info.ComposeHash = retired
		c.encodeReport(t)
		if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "workload identity") {
			t.Fatalf("retired compose %s must not remain eligible, got %v", retired[:8], err)
		}
	}
}
