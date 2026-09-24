//go:build cloud_aws

package bedrock

import (
	"fmt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/testutil/fundedrequest"
	"testing"
)

func TestFundedInnerNativeBedrockWire(t *testing.T) {
	for _, total := range []int{1, 800, 1024, 1025, 8192, 32768, 60000} {
		for _, hint := range []any{map[string]any{"max_tokens": 32768}, map[string]any{"budget_tokens": 60000}, map[string]any{"thinking_budget": -1}, map[string]any{"effort": "high"}} {
			t.Run(fmt.Sprintf("%d/%v", total, hint), func(t *testing.T) {
				_, body, authorized := fundedrequest.New(t, total, hint, "")
				fundedrequest.Check(t, buildAnthropicBedrockWireRequest(body), authorized, false)
			})
		}
	}
}
