//go:build llm_multi

package llm

import "testing"

// The Anthropic and Bedrock Runtime route tables exist only in the multi
// build. The source walk in TestEveryKnownClaudeModelHasAReasoningClass reads
// them under every tag set; this walks them in memory as well.
func TestMultiBuildRouteTableClaudeModelsAreListed(t *testing.T) {
	for name, table := range map[string]map[string]string{"modelIDMap": modelIDMap, "bedrockRuntimeModels": bedrockRuntimeModels} {
		claudeRouteTableIsListed(t, name, table)
	}
}
