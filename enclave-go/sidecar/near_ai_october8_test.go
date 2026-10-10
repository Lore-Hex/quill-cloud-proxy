package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNearAIReviewedOctober9GPU03(t *testing.T) {
	c := reviewedNearAIPoolCase(t, "55db164f4f8c6a837c2217c601c21bba4758f908536a6cd5b2978550205a9179")
	if c.policy.DeploymentCommit != "b9acc8f208409daa2c35d26f0b7bbd93ecc5eef5" ||
		c.policy.DeploymentSHA256 != "a49d9c15e866c6f569655fb506a0c60cf97e70c01a6de580c1a4fac0a1e334be" ||
		c.policy.DeploymentActionsSHA256 != "232ae6c935e27f5fd256936b8ddba67ebe8b7ff984eb8d753524b43ff59f62ac" {
		t.Fatal("gpu03 must pin the exact reviewed source and complete history")
	}
	var actions []nearAIDeploymentAction
	if err := json.Unmarshal(c.report.ComposeManager.Actions, &actions); err != nil {
		t.Fatal(err)
	}
	// Every engine must have an explicit matching deployment. Telemetry
	// stays on its separately reviewed October 8 configuration.
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
		commit, digest := c.policy.DeploymentCommit, c.policy.DeploymentSHA256
		if service == "glm53-ghost-aggregator" || service == "otelcol-contrib" {
			commit = "1121ee56851dcec7dc89e60099d7be28fc51a73e"
			digest = "b0077025ac5f099ca6b30dd21a2605e3ba600b01be38e1605b5ec93f69a125da"
		}
		if latest == nil || latest.Action != "compose_up" || latest.File != c.policy.DeploymentFile ||
			latest.Commit != commit || latest.FileSHA256 != digest {
			t.Fatalf("%s does not have a matching reviewed deployment: %+v", service, latest)
		}
	}
	if _, err := c.verifier.verify(context.Background(), c.request); err != nil {
		t.Fatalf("reviewed gpu03 history rejected: %v", err)
	}
	old, err := os.ReadFile(filepath.Join("testdata", "near-ai-2026-10-08", "55db164f-actions.json"))
	if err != nil {
		t.Fatal(err)
	}
	bindNearAITestActions(t, c, old)
	if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "deployment history") {
		t.Fatalf("superseded October 8 history accepted: %v", err)
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

func TestNearAIOctober9GPU04RemainsUnreviewed(t *testing.T) {
	c := reviewedNearAIPoolCase(t, "c82b1a2eaf6996154a5f39ae621643f034b082d5e51edd3d2ba6009273881d86")
	actions, err := os.ReadFile(filepath.Join("testdata", "near-ai-2026-10-09", "c82b1a2e-unreviewed-actions.json"))
	if err != nil {
		t.Fatal(err)
	}
	bindNearAITestActions(t, c, actions)
	if c.report.ComposeManager.ActionsHash != "4c6eb48f299c533df1ed2b79d098333a0d694bbfe6c8b23b71da882689ea177b" {
		t.Fatal("gpu04 fixture differs from the current unreviewed history")
	}
	if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "deployment history") {
		t.Fatalf("gpu04 must not inherit gpu03's independent review: %v", err)
	}
}
