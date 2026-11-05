//go:build llm_multi

package llm

import "testing"

func TestBasetenBeamAcceptsAssistantTurnsWithoutReasoning(t *testing.T) {
	wire := buildOpenAICompatibleRequest("baseten", "reflection/Beam-1.0", nil, nil, nil)
	if wire.AllowMissingThinking == nil || !*wire.AllowMissingThinking {
		t.Fatal("Beam on Baseten must accept assistant turns sent back without reasoning")
	}
	for _, other := range [][2]string{
		{"baseten", "zai-org/GLM-4.7"},
		{"io-net", "reflection/Beam-1.0-501B-A23B"},
		{"openai", "gpt-4o"},
	} {
		if wire := buildOpenAICompatibleRequest(other[0], other[1], nil, nil, nil); wire.AllowMissingThinking != nil {
			t.Fatalf("%s %s: sent allow_missing_thinking to an unreviewed route", other[0], other[1])
		}
	}
}
