package speculation

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestSeamAdapterParity(t *testing.T) {
	routes := [][2]string{{"fixture-provider", "fixture-text"}, {"openai", "gpt-4o"}, {"openai", "gpt-5.5"}, {"azure", "codestral-2501"}, {"azure", "kimi-k2-5"}, {"kimi", "kimi-k2.5"}, {"google-ai-studio", "gemini-2.5-flash"}, {"gemini", "gemini-3.7-flash"}, {"engy", "qwen3.6-35b-a3b"}, {"perplexity", "sonar"}, {"tinfoil", "llama"}, {"neurometric", "neurometric/structured-decisions"}}
	for _, route := range routes {
		for _, explicit := range []bool{false, true} {
			for _, system := range []bool{false, true} {
				t.Run(route[0]+"/"+route[1]+"/"+map[bool]string{false: "implicit", true: "explicit"}[explicit]+"/"+map[bool]string{false: "plain", true: "system"}[system], func(t *testing.T) {
					c := eligibleCase(t)
					h := newHarness(t)
					claims, _ := h.real.Claims()
					signedRoute := m(claims["route"])
					signedRoute["provider"], signedRoute["upstream_model"] = route[0], route[1]
					context := m(h.bundle["context"])
					context["route"] = signedRoute
					grant, err := VerifyGrant(signedEligibilityToken(t, h, claims, RealTyp), h.keys, context, 1700000000, false)
					if err != nil {
						t.Fatal(err)
					}
					c.local.Certificates[0].Route = signedRoute
					if route[0] == "tinfoil" {
						c.local.Certificates[0].ProviderCacheScope = "workspace-scope"
					}
					c.req.Body["model"] = route[1]
					c.req.Body["messages"] = []any{map[string]any{"role": "user", "content": "雪🙂<>&"}, map[string]any{"role": "assistant", "content": "answer"}, map[string]any{"role": "user", "content": ""}}
					if explicit {
						c.req.Body["temperature"] = 0.25
						c.req.Body["top_p"] = 0.8
						c.req.Body["stop"] = []any{"STOP", "終"}
						c.req.Body["seed"] = int64(42)
						c.req.Body["frequency_penalty"] = 0.2
						c.req.Body["presence_penalty"] = 0.3
						c.req.Body["logit_bias"] = map[string]any{"2": int64(-1)}
						c.req.Body["logprobs"] = true
						c.req.Body["top_logprobs"] = int64(2)
						c.req.Body["service_tier"] = "default"
						c.req.Body["stream_options"] = map[string]any{"include_usage": false}
					}
					if system {
						c.local.Certificates[0].SystemPrefix = []string{"prefix", "addition"}
						c.req.Body["messages"] = append(c.req.Body["messages"].([]any), map[string]any{"role": "system", "content": "caller system"})
					}
					got, r := PreparePayload(grant, c.local.Certificates, c.req)
					if r != ReasonEligible {
						t.Fatal(r)
					}
					raw, _ := json.Marshal(c.req.Body)
					var req qtypes.OpenAIChatRequest
					if err := json.Unmarshal(raw, &req); err != nil {
						t.Fatal(err)
					}
					if system {
						req.Messages = append([]qtypes.OpenAIChatMessage{{Role: "system", Content: "prefix"}, {Role: "system", Content: "addition"}}, req.Messages...)
					}
					body, err := adapter.ToAnthropic(&req, route[1])
					if err != nil {
						t.Fatal(err)
					}
					msgs := []llm.ChatMessage{}
					if body.System != "" {
						msgs = append(msgs, llm.ChatMessage{Role: "system", Content: body.System})
					}
					for _, msg := range body.Messages {
						msgs = append(msgs, llm.ChatMessage{Role: msg.Role, Content: msg.Content})
					}
					want, err := llm.PrepareChatRequest(route[0], route[1], &req, body, msgs, llm.ChatPreparationOptions{ProviderCacheScope: c.local.Certificates[0].ProviderCacheScope})
					if err != nil || !bytes.Equal(got.Bytes, want.Bytes) || got.SHA256 != digest(want.Bytes) {
						t.Fatalf("seam/ordinary divergence: %v\n%s\n%s", err, got.Bytes, want.Bytes)
					}
					if explicit && !bytes.Contains(got.Bytes, []byte(`"stop":["STOP","終"]`)) {
						t.Fatal("stop lost")
					}
					if system && !bytes.Contains(got.Bytes, []byte(`{"role":"system","content":"prefix\n\naddition\n\ncaller system"}`)) {
						t.Fatal("system role or normalization lost")
					}
				})
			}
		}
	}
}
