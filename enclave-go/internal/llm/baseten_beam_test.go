//go:build llm_multi

package llm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBasetenBeamAcceptsAssistantTurnsWithoutReasoning(t *testing.T) {
	encoded, err := json.Marshal(buildOpenAICompatibleRequest("baseten", "reflection/Beam-1.0", nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	// Baseten honours the flag only inside chat_template_kwargs (verified
	// against the live endpoint: top-level, extra_body and string forms 400).
	if _, topLevel := wire["allow_missing_thinking"]; topLevel {
		t.Fatalf("allow_missing_thinking must not be top-level, Baseten ignores it there: %s", encoded)
	}
	kwargs, _ := wire["chat_template_kwargs"].(map[string]any)
	if kwargs["allow_missing_thinking"] != true {
		t.Fatalf("Beam on Baseten must send chat_template_kwargs.allow_missing_thinking=true: %s", encoded)
	}
	if _, set := kwargs["enable_thinking"]; set {
		t.Fatalf("Beam must keep thinking on; enable_thinking must be absent: %s", encoded)
	}
	for _, other := range [][2]string{
		{"baseten", "zai-org/GLM-4.7"},
		{"io-net", "reflection/Beam-1.0-501B-A23B"},
		{"openai", "gpt-4o"},
	} {
		encoded, err := json.Marshal(buildOpenAICompatibleRequest(other[0], other[1], nil, nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "allow_missing_thinking") {
			t.Fatalf("%s %s: sent allow_missing_thinking to an unreviewed route: %s", other[0], other[1], encoded)
		}
	}
}
