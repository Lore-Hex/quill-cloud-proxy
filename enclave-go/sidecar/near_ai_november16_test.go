package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// docs/near-ai-policy-review-2026-11-16.md: gpu03 (instance 19aea169) kept
// its November 12 boot (compose c900dc73, same event log) and redeployed only
// its proxy and registrar, twice: v0.0.581 on November 13 and v0.0.593 on
// November 14. The engines still run the November 12 v0.0.567 file. Only these
// exact sources were reviewed.
type nearAIReviewedSource struct{ file, commit, sha256 string }

var (
	// v0.0.593: proxy-glm53 on nearaidev/vllm-proxy-rs@sha256:c57cd9ea...
	// and model-proxy-registrar. This is the policy pin.
	nearAIV0593Proxy = nearAIReviewedSource{
		"prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml",
		"7d62ec6762bb1288ea5d5cf40b05e8a7c5305df9",
		"08a56ab2437cd75ba613c8f4dc6022747e59311b571844b0d3da42003188911a",
	}
	// v0.0.567: r1-r4 on nearaidev/sglang@sha256:050b1adf..., the November 12
	// policy pin.
	nearAIV0523Fleet = nearAIReviewedSource{
		"prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml",
		"dfbb641fdf3fb98ab38078300a39526c7945db18",
		"2d10ba2c3dbcf021ccf888f180c23454c3209736f00836093c583af0f2f742df",
	}
	// v0.0.541: the November 6 policy pin, still serving nginx.
	nearAIV12Q8Edge = nearAIReviewedSource{
		"prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml",
		"5a5119f799409672cfd101429b01dcd6db30188e",
		"309c07af98ff96349716dde078158ee021cf0eed33cd8690aa638f2e61546dd1",
	}
)

func latestNearAIServiceActions(t *testing.T, raw json.RawMessage) map[string]nearAIDeploymentAction {
	t.Helper()
	var actions []nearAIDeploymentAction
	if err := json.Unmarshal(raw, &actions); err != nil {
		t.Fatal(err)
	}
	latest := make(map[string]nearAIDeploymentAction)
	for _, action := range actions {
		for _, service := range action.Services {
			latest[service] = action
		}
	}
	return latest
}

func TestNearAIReviewedNovember16Pool(t *testing.T) {
	const actionsSHA = "6a66ec22a079334155f064f084066ae4dcb310a2398c7031797a4ad4244e1600"
	serving := map[string]nearAIReviewedSource{
		"model-sg-glm53-w4afp8-tp2-r1": nearAIV0523Fleet,
		"model-sg-glm53-w4afp8-tp2-r2": nearAIV0523Fleet,
		"model-sg-glm53-w4afp8-tp2-r3": nearAIV0523Fleet,
		"model-sg-glm53-w4afp8-tp2-r4": nearAIV0523Fleet,
		"otelcol-contrib":              nearAIV0523Fleet,
		"proxy-glm53":                  nearAIV0593Proxy,
		"model-proxy-registrar":        nearAIV0593Proxy,
		"nginx":                        nearAIV12Q8Edge,
		"model-downloader":             nearAIV12Q8Edge,
	}
	c := reviewedNearAIPoolCase(t, nearAIGPU03Compose)
	pin := nearAIV0593Proxy
	if c.policy.DeploymentFile != pin.file || c.policy.DeploymentCommit != pin.commit ||
		c.policy.DeploymentSHA256 != pin.sha256 || c.policy.DeploymentActionsSHA256 != actionsSHA {
		t.Fatalf("gpu03 must pin its exact reviewed source and complete history: %+v", c.policy)
	}
	if c.report.ComposeManager.ActionsHash != actionsSHA {
		t.Fatal("fixture differs from the reviewed history")
	}
	latest := latestNearAIServiceActions(t, c.report.ComposeManager.Actions)
	for service, source := range serving {
		action, ok := latest[service]
		if !ok || action.Action != "compose_up" || action.File != source.file ||
			action.Commit != source.commit || action.FileSHA256 != source.sha256 {
			t.Fatalf("%s does not have its reviewed deployment: %+v", service, action)
		}
	}
	// The one-shot compose-manager token rotation must not be left running.
	if latest["rotate-token"].Action != "compose_down" {
		t.Fatalf("rotate-token must be stopped: %+v", latest["rotate-token"])
	}
	// v0.0.593 dropped the verification-only soak relay from the file; it has
	// been stopped since October 19 and must stay stopped.
	if latest["glm53-soak-relay"].Action != "compose_down" {
		t.Fatalf("glm53-soak-relay must be stopped: %+v", latest["glm53-soak-relay"])
	}
	if _, err := c.verifier.verify(context.Background(), c.request); err != nil {
		t.Fatalf("reviewed gpu03 history rejected: %v", err)
	}
}

func TestNearAINovember16PoolRequiresDstack0512Identity(t *testing.T) {
	const retiredOSImage = "a6eafc5f007f642d8ea90c7fa8881f1e6715720ccb531941a28218f4f26d7b02"
	c := reviewedNearAIPoolCase(t, nearAIGPU03Compose)
	if c.policy.OSImageHash != "91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829" {
		t.Fatal("pool must pin the dstack-nvidia-0.5.12 OS image")
	}
	c.report.Info.OSImageHash = retiredOSImage
	c.encodeReport(t)
	if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "workload identity") {
		t.Fatalf("0.5.11 OS image accepted for the 0.5.12 pool: %v", err)
	}

	// The small-models CVM reports app_name dstack-nvidia-0.5.12; the
	// reviewed gpu03 manifest is still named dstack-nvidia-0.5.11.
	c = reviewedNearAIPoolCase(t, nearAIGPU03Compose)
	c.report.Info.AppName = "dstack-nvidia-0.5.12"
	c.encodeReport(t)
	if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "workload identity") {
		t.Fatalf("changed app name accepted: %v", err)
	}

	// The kernel (RTMR1) and initrd/cmdline (RTMR2) registers of the retired
	// 0.5.11 guests must not satisfy the boot pins.
	for index, old := range map[int]string{
		1: "ff61e68fa04516b1813d2d478397a97a58f9ccc402b6d96fb73f5e5104a4acf155913caec99a0c19afc16ae0f3a77726",
		2: "4d662c04766145dfe084fd014969b19c387afe9bb1d4f972c6968d28a7a8b4937c414603a2cf446105eddce67a86f9ce",
	} {
		for _, stage := range []string{"model", "manager"} {
			changed := reviewedNearAIPoolCase(t, nearAIGPU03Compose)
			body := changed.modelBody
			if stage == "manager" {
				body = changed.managerBody
			}
			body.Rtmrs[index], _ = hex.DecodeString(old)
			if _, err := changed.verifier.verify(context.Background(), changed.request); err == nil || !strings.Contains(err.Error(), "boot measurement") {
				t.Fatalf("0.5.11 RTMR%d accepted on the %s quote: %v", index, stage, err)
			}
		}
	}
}
