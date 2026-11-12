package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// docs/near-ai-policy-review-2026-11-12.md: gpu03 (instance 19aea169) booted a
// new base manifest on the same dstack-nvidia-0.5.12 image and rolled its
// engines to SGLang v0.5.23 and a new proxy. gpu04 left the pool. Only these
// exact sources were reviewed.
type nearAIReviewedSource struct{ file, commit, sha256 string }

var (
	// v0.0.567: r1-r4 on nearaidev/sglang@sha256:050b1adf..., proxy
	// nearaidev/vllm-proxy-rs@sha256:e2893ff4.... This is the policy pin.
	nearAIV0523Fleet = nearAIReviewedSource{
		"prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml",
		"dfbb641fdf3fb98ab38078300a39526c7945db18",
		"2d10ba2c3dbcf021ccf888f180c23454c3209736f00836093c583af0f2f742df",
	}
	// v0.0.554: the registrar's last compose_up. Same bytes as v0.0.553.
	nearAIV12Q8Registrar = nearAIReviewedSource{
		"prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml",
		"fe7493ee3a0b3d36c1079c095de554e7b218da5c",
		"e88b040e8ecdb7869ac855880719f6d184c035f0199753bef64ed338f8622922",
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

func TestNearAIReviewedNovember12Pool(t *testing.T) {
	const actionsSHA = "e196ae7210ec5344b3c0c78b918126a195ff37b8e116fb0766e7df9e55180faa"
	serving := map[string]nearAIReviewedSource{
		"model-sg-glm53-w4afp8-tp2-r1": nearAIV0523Fleet,
		"model-sg-glm53-w4afp8-tp2-r2": nearAIV0523Fleet,
		"model-sg-glm53-w4afp8-tp2-r3": nearAIV0523Fleet,
		"model-sg-glm53-w4afp8-tp2-r4": nearAIV0523Fleet,
		"otelcol-contrib":              nearAIV0523Fleet,
		"proxy-glm53":                  nearAIV0523Fleet,
		"model-proxy-registrar":        nearAIV12Q8Registrar,
		"nginx":                        nearAIV12Q8Edge,
		"model-downloader":             nearAIV12Q8Edge,
	}
	c := reviewedNearAIPoolCase(t, nearAIGPU03Compose)
	pin := nearAIV0523Fleet
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
	if _, err := c.verifier.verify(context.Background(), c.request); err != nil {
		t.Fatalf("reviewed gpu03 history rejected: %v", err)
	}
}

func TestNearAINovember12PoolRequiresDstack0512Identity(t *testing.T) {
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
