//go:build llm_multi && live_provider_wave

package llm

import (
	"os"
	"testing"
)

func TestLiveRegoloDecisionBYOK(t *testing.T) {
	key := os.Getenv("REGOLO_API_KEY")
	if key == "" || os.Getenv("TR_LIVE_REGOLO_DECIDE") != "1" {
		t.Skip("set REGOLO_API_KEY and TR_LIVE_REGOLO_DECIDE=1 for paid smoke")
	}
	runLiveRegoloDecision(t, &multiClient{}, InvokeOptions{
		Provider: "regolo", UpstreamModel: "clef-flash", UsageType: "BYOK", ProviderAPIKey: key,
	})
}
