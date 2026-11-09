package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs/near-ai-policy-review-2026-11-06.md: both GLM 5.3 Flash instances
// rebooted onto dstack-nvidia-0.5.12 with new base manifests and updated
// engine/proxy deployments. Only these exact sources were reviewed.
type nearAIReviewedSource struct{ file, commit, sha256 string }

var (
	nearAIV12Q8Engines = nearAIReviewedSource{
		"prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml",
		"7ee4a4c741259d0c69a81e5cda22c3dfce21cbc2",
		"904054f502ccdb2f913d6b80f156ea658b8bc5cb6f8af06082723581d62a45c0",
	}
	nearAIV12Q8Proxy = nearAIReviewedSource{
		"prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml",
		"5a5119f799409672cfd101429b01dcd6db30188e",
		"309c07af98ff96349716dde078158ee021cf0eed33cd8690aa638f2e61546dd1",
	}
	nearAIV8KdaEdge = nearAIReviewedSource{
		"prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V8KdaCanary.yaml",
		"8977a0e8383685752d4a43621c9226bbaccd857d",
		"9f1981bc7bec1477af24bf51bab2959e376cde8a350b35b95fe18d7fd8ac6329",
	}
	nearAIGPU04Mixed = nearAIReviewedSource{
		"prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8-gpu04-3B1L.yaml",
		"410345d5a9880b71e76aa5daa1dcfc24f7cb8341",
		"6ce091c9c12d2024263fa54d3ccc2a9a54ecf04d13de203989ed0b1fe344ff1a",
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

func TestNearAIReviewedNovember6Pool(t *testing.T) {
	cases := map[string]struct {
		pin        nearAIReviewedSource
		actionsSHA string
		serving    map[string]nearAIReviewedSource
		stopped    []string
	}{
		"gpu03": {
			pin:        nearAIV12Q8Proxy,
			actionsSHA: "4f6a87d47b9584343a5484bb456ca1dfe8d678379855fead236caf8e0289d82e",
			serving: map[string]nearAIReviewedSource{
				"model-sg-glm53-w4afp8-tp2-r1": nearAIV12Q8Engines,
				"model-sg-glm53-w4afp8-tp2-r2": nearAIV12Q8Engines,
				"model-sg-glm53-w4afp8-tp2-r3": nearAIV12Q8Engines,
				"model-sg-glm53-w4afp8-tp2-r4": nearAIV12Q8Engines,
				"otelcol-contrib":              nearAIV12Q8Engines,
				"proxy-glm53":                  nearAIV12Q8Proxy,
				"nginx":                        nearAIV8KdaEdge,
				"model-proxy-registrar":        nearAIV8KdaEdge,
			},
		},
		"gpu04": {
			pin:        nearAIGPU04Mixed,
			actionsSHA: "641a324566305d1771de6784003e3967dad18988c74274b974066573e3b9af49",
			serving: map[string]nearAIReviewedSource{
				"model-sg-glm53-w4afp8-tp2-r1": nearAIV12Q8Engines,
				"model-sg-glm53-w4afp8-tp2-r2": nearAIV12Q8Engines,
				"model-sg-glm53-w4afp8-tp2-r3": nearAIV12Q8Engines,
				"model-sg-glm53-w4afp8-tp2-l4": nearAIGPU04Mixed,
				"proxy-glm53":                  nearAIGPU04Mixed,
				"proxy-glm53-long":             nearAIGPU04Mixed,
				"nginx":                        nearAIGPU04Mixed,
				"model-proxy-registrar":        nearAIGPU04Mixed,
				"otelcol-contrib":              nearAIGPU04Mixed,
			},
			// The base r4 engine was replaced by the long-context l4 replica.
			stopped: []string{"model-sg-glm53-w4afp8-tp2-r4"},
		},
	}
	composes := map[string]string{"gpu03": nearAIGPU03Compose, "gpu04": nearAIGPU04Compose}
	for host, want := range cases {
		t.Run(host, func(t *testing.T) {
			c := reviewedNearAIPoolCase(t, composes[host])
			if c.policy.DeploymentFile != want.pin.file || c.policy.DeploymentCommit != want.pin.commit ||
				c.policy.DeploymentSHA256 != want.pin.sha256 || c.policy.DeploymentActionsSHA256 != want.actionsSHA {
				t.Fatalf("%s must pin its exact reviewed source and complete history: %+v", host, c.policy)
			}
			if c.report.ComposeManager.ActionsHash != want.actionsSHA {
				t.Fatalf("%s fixture differs from the reviewed history", host)
			}
			latest := latestNearAIServiceActions(t, c.report.ComposeManager.Actions)
			for service, source := range want.serving {
				action, ok := latest[service]
				if !ok || action.Action != "compose_up" || action.File != source.file ||
					action.Commit != source.commit || action.FileSHA256 != source.sha256 {
					t.Fatalf("%s %s does not have its reviewed deployment: %+v", host, service, action)
				}
			}
			for _, service := range want.stopped {
				if latest[service].Action != "compose_down" {
					t.Fatalf("%s %s must be stopped: %+v", host, service, latest[service])
				}
			}
			if _, err := c.verifier.verify(context.Background(), c.request); err != nil {
				t.Fatalf("reviewed %s history rejected: %v", host, err)
			}
		})
	}
}

func TestNearAINovember6PoolRequiresDstack0512Identity(t *testing.T) {
	const retiredOSImage = "a6eafc5f007f642d8ea90c7fa8881f1e6715720ccb531941a28218f4f26d7b02"
	for _, compose := range []string{nearAIGPU03Compose, nearAIGPU04Compose} {
		t.Run(compose[:8], func(t *testing.T) {
			c := reviewedNearAIPoolCase(t, compose)
			if c.policy.OSImageHash != "91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829" {
				t.Fatal("pool must pin the dstack-nvidia-0.5.12 OS image")
			}
			c.report.Info.OSImageHash = retiredOSImage
			c.encodeReport(t)
			if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "workload identity") {
				t.Fatalf("0.5.11 OS image accepted for the 0.5.12 pool: %v", err)
			}

			// The kernel (RTMR1) and initrd/cmdline (RTMR2) registers of the
			// retired 0.5.11 guests must not satisfy the new boot pins.
			for index, old := range map[int]string{
				1: "ff61e68fa04516b1813d2d478397a97a58f9ccc402b6d96fb73f5e5104a4acf155913caec99a0c19afc16ae0f3a77726",
				2: "4d662c04766145dfe084fd014969b19c387afe9bb1d4f972c6968d28a7a8b4937c414603a2cf446105eddce67a86f9ce",
			} {
				for _, stage := range []string{"model", "manager"} {
					changed := reviewedNearAIPoolCase(t, compose)
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
		})
	}
}

func TestNearAINovember6RejectsEarlierGPU04Histories(t *testing.T) {
	for _, fixture := range []string{
		filepath.Join("near-ai-2026-10-03", "c82b1a2e-actions.json"),
		filepath.Join("near-ai-2026-10-08", "c82b1a2e-unreviewed-actions.json"),
		filepath.Join("near-ai-2026-10-09", "c82b1a2e-unreviewed-actions.json"),
	} {
		c := reviewedNearAIPoolCase(t, nearAIGPU04Compose)
		actions, err := os.ReadFile(filepath.Join("testdata", fixture))
		if err != nil {
			t.Fatal(err)
		}
		bindNearAITestActions(t, c, actions)
		if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "deployment history") {
			t.Fatalf("%s accepted under the reviewed gpu04 policy: %v", fixture, err)
		}
	}
}
