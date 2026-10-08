package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNearAIReviewedOctober8GPU03(t *testing.T) {
	c := reviewedNearAIPoolCase(t, "55db164f4f8c6a837c2217c601c21bba4758f908536a6cd5b2978550205a9179")
	if c.policy.DeploymentCommit != "1121ee56851dcec7dc89e60099d7be28fc51a73e" ||
		c.policy.DeploymentSHA256 != "b0077025ac5f099ca6b30dd21a2605e3ba600b01be38e1605b5ec93f69a125da" ||
		c.policy.DeploymentActionsSHA256 != "cca6a43ace213e309dc9483adf895f98cde49551c7dd7eaeefcb40afde0ce980" {
		t.Fatal("gpu03 must pin the exact reviewed source and complete history")
	}
	var actions []nearAIDeploymentAction
	if err := json.Unmarshal(c.report.ComposeManager.Actions, &actions); err != nil {
		t.Fatal(err)
	}
	// The last action is telemetry-only. Every engine must have an earlier,
	// explicit matching deployment, not merely inherit that last file's pin.
	for _, service := range []string{
		"model-sg-glm53-w4afp8-tp2-r1", "model-sg-glm53-w4afp8-tp2-r2",
		"model-sg-glm53-w4afp8-tp2-r3", "model-sg-glm53-w4afp8-tp2-r4",
		"glm53-ghost-aggregator", "otelcol-contrib",
	} {
		var latest *nearAIDeploymentAction
		for i := range actions {
			for _, deployed := range actions[i].Services {
				if deployed == service {
					latest = &actions[i]
				}
			}
		}
		if latest == nil || latest.Action != "compose_up" || latest.File != c.policy.DeploymentFile ||
			latest.Commit != c.policy.DeploymentCommit || latest.FileSHA256 != c.policy.DeploymentSHA256 {
			t.Fatalf("%s does not have a matching reviewed deployment: %+v", service, latest)
		}
	}
	if _, err := c.verifier.verify(context.Background(), c.request); err != nil {
		t.Fatalf("reviewed gpu03 history rejected: %v", err)
	}
	old, err := os.ReadFile(filepath.Join("testdata", "near-ai-2026-10-03", "55db164f-actions.json"))
	if err != nil {
		t.Fatal(err)
	}
	bindNearAITestActions(t, c, old)
	if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "deployment history") {
		t.Fatalf("superseded October 3 history accepted: %v", err)
	}
}

func TestNearAIOctober8MixedGPU04RemainsUnreviewed(t *testing.T) {
	c := reviewedNearAIPoolCase(t, "c82b1a2eaf6996154a5f39ae621643f034b082d5e51edd3d2ba6009273881d86")
	if c.policy.DeploymentActionsSHA256 != "281432886e04b7b19bc55793085fcbdf812eb2d7479e409e4a7b283e21ac069d" ||
		c.policy.DeploymentCommit != "93aa1121f736406acd10730fa9f8caf2fe045aa3" {
		t.Fatal("gpu04 must retain its independently reviewed October 3 policy")
	}
	actions, err := os.ReadFile(filepath.Join("testdata", "near-ai-2026-10-08", "c82b1a2e-unreviewed-actions.json"))
	if err != nil {
		t.Fatal(err)
	}
	bindNearAITestActions(t, c, actions)
	if c.report.ComposeManager.ActionsHash != "f683de2f8e143bc4337c178af952a28ff4a9c53bd09b7cd2bf8f71f74ce88abc" {
		t.Fatal("unreviewed gpu04 fixture does not match the observed mixed history")
	}
	if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "deployment history") {
		t.Fatalf("unreviewed mixed peer-KV deployment accepted: %v", err)
	}
}
