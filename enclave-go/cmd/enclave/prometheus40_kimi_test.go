package main

import (
	"slices"
	"testing"
)

func TestPrometheus40UsesKimiK31ProAndZeus30KeepsKimiK3(t *testing.T) {
	stages := func(model string) []string {
		_, panel, _ := fusionPresetPanelForModel(model)
		judges, _ := fusionPresetJudgeModelsForModel(model)
		finals, _ := fusionPresetFinalModelsForModel(model)
		return append(append(panel, judges...), finals...)
	}
	for _, model := range []string{trustedRouterPrometheusModel, trustedRouterPrometheus40Model} {
		members := stages(model)
		if slices.Contains(members, "moonshotai/kimi-k3") {
			t.Fatalf("%s still uses Kimi K3: %v", model, members)
		}
		for _, stage := range [][]string{fusionPrometheus40Panel, fusionPrometheus40JudgeModels, fusionPrometheus40FinalModels} {
			if !slices.Contains(stage, "moonshotai/kimi-k3.1-pro") {
				t.Fatalf("%s stage lacks Kimi K3.1 Pro: %v", model, stage)
			}
		}
	}
	for _, model := range []string{trustedRouterZeusModel, trustedRouterZeus30Model} {
		members := stages(model)
		if slices.Contains(members, "moonshotai/kimi-k3.1-pro") || !slices.Contains(members, "moonshotai/kimi-k3") {
			t.Fatalf("%s changed Kimi: %v", model, members)
		}
	}
	if got := longContextComboProviders["moonshotai/kimi-k3.1-pro"]; len(got) < 2 || slices.Contains(got, "deepinfra") {
		t.Fatalf("Kimi K3.1 Pro long-context route: %v", got)
	}
}
