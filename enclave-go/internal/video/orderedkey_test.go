package video

import (
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/orderedkey"
)

func TestInvalidStandbyCannotOpenNewJobs(t *testing.T) {
	r := NewRegistry(ProviderKeys{FAL: "a", FALStandby: "a", MiniMax: "b", MiniMaxStandby: "b"}, nil)
	for _, id := range []string{"fal", "minimax"} {
		for _, decision := range []string{"", "primary:" + strings.Repeat("a", 64), strings.Repeat("a", 64)} {
			if _, ok := r.ForGeneration(id, decision); ok {
				t.Fatal("invalid credential pair authorized a new job")
			}
		}
		if _, _, ok := r.ForJob(id, "native"); !ok {
			t.Fatal("existing primary job lost access to its submitting key")
		}
	}
}

func TestJobsUseSubmittingSlotAcrossRegistryRestart(t *testing.T) {
	keys := ProviderKeys{FAL: "a", FALStandby: "b", MiniMax: "a", MiniMaxStandby: "b"}
	for _, id := range []string{"fal", "minimax"} {
		gen := orderedkey.Generation(id, "a", "b")
		standbyModel := BindJobModel("native", gen)
		afterRestart := NewRegistry(keys, nil)
		for _, tc := range []struct{ model, want string }{
			{BindJobModel("native", ""), "a"}, {standbyModel, "b"},
			{BindJobModel("native", "old-generation"), ""}, {"tr-slot2::native", ""},
		} {
			p, raw, ok := afterRestart.ForJob(id, tc.model)
			if !ok {
				if tc.want != "" {
					t.Fatal("lost job after restart")
				}
				continue
			}
			if raw != "native" {
				t.Fatal("provider would receive an internal marker")
			}
			var got string
			switch c := p.(type) {
			case *FALVideoClient:
				got = c.apiKey
			case *MiniMaxClient:
				got = c.apiKey
			default:
				t.Fatal("wrong provider")
			}
			if got != tc.want {
				t.Fatal("wrong submitting account")
			}
		}
		if _, _, ok := NewRegistry(ProviderKeys{FAL: "a", MiniMax: "a"}, nil).ForJob(id, standbyModel); ok {
			t.Fatal("missing standby silently replaced with primary")
		}
	}
}
