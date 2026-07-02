package llm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// TestChatCacheControlSurvivesToAnthropicPayload is the conformance guard for
// the prompt-cache passthrough fix: a client cache_control breakpoint set on a
// user content block on /v1/chat/completions must survive the OpenAI->Anthropic
// translation all the way into the upstream /v1/messages payload. Before the
// fix, chatPartFromAny/anthropicPartsWithFetchedImages rebuilt each block as a
// fresh {type,text} map and silently dropped cache_control, so caching never
// engaged on the chat path (while /v1/messages, which passes content verbatim,
// worked). QuillCode PR #908 (issue #857) emits exactly this shape.
func TestChatCacheControlSurvivesToAnthropicPayload(t *testing.T) {
	const reqJSON = `{
		"model": "anthropic/claude-haiku-4.5",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": [
				{"type": "text", "text": "long cached prefix", "cache_control": {"type": "ephemeral"}}
			]}
		]
	}`

	var req qtypes.OpenAIChatRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	body, err := adapter.ToAnthropic(&req, "")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	if body.NativeContent {
		t.Fatalf("chat path must not be marked NativeContent")
	}

	// anthropicUpstreamMessages is exactly what anthropic.go feeds into the
	// upstream Anthropic Messages body for the /v1/chat/completions path.
	msgs, err := anthropicUpstreamMessages(t.Context(), body)
	if err != nil {
		t.Fatalf("anthropicUpstreamMessages: %v", err)
	}

	raw, err := json.Marshal(msgs)
	if err != nil {
		t.Fatalf("marshal messages: %v", err)
	}
	if !strings.Contains(string(raw), `"cache_control"`) {
		t.Fatalf("upstream Anthropic payload dropped cache_control: %s", raw)
	}

	cc := firstUserBlockCacheControl(t, msgs)
	if got := cc["type"]; got != "ephemeral" {
		t.Fatalf("cache_control.type = %v, want ephemeral (payload=%s)", got, raw)
	}
}

// TestChatSystemCacheControlSurvivesToAnthropicPayload guards the highest-value
// case: a client cache_control breakpoint on the SYSTEM prompt must reach the
// upstream Anthropic `system` field. ToAnthropic promotes system to content
// blocks (SystemRaw) when a breakpoint is present, and anthropicSystemField
// (what anthropic.go/byok.go/gcp.go send upstream) surfaces it rather than the
// flattened string.
func TestChatSystemCacheControlSurvivesToAnthropicPayload(t *testing.T) {
	const reqJSON = `{
		"model": "anthropic/claude-haiku-4.5",
		"messages": [
			{"role": "system", "content": [
				{"type": "text", "text": "large cached system prefix", "cache_control": {"type": "ephemeral"}}
			]},
			{"role": "user", "content": "hi"}
		]
	}`
	var req qtypes.OpenAIChatRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	body, err := adapter.ToAnthropic(&req, "")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	raw, err := json.Marshal(anthropicSystemField(body))
	if err != nil {
		t.Fatalf("marshal system field: %v", err)
	}
	if !strings.Contains(string(raw), `"cache_control"`) || !strings.Contains(string(raw), "ephemeral") {
		t.Fatalf("upstream Anthropic system field dropped cache_control: %s", raw)
	}
	if !strings.Contains(string(raw), "large cached system prefix") {
		t.Fatalf("system text missing from system field: %s", raw)
	}
}

// TestChatSystemWithoutCacheControlStaysString verifies the common case is
// unchanged: a plain string system prompt (no breakpoint) is sent as a bare
// string, not promoted to content blocks.
func TestChatSystemWithoutCacheControlStaysString(t *testing.T) {
	const reqJSON = `{
		"model": "anthropic/claude-haiku-4.5",
		"messages": [
			{"role": "system", "content": "plain system"},
			{"role": "user", "content": "hi"}
		]
	}`
	var req qtypes.OpenAIChatRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	body, err := adapter.ToAnthropic(&req, "")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	if _, ok := anthropicSystemField(body).(string); !ok {
		t.Fatalf("expected bare string system field, got %T", anthropicSystemField(body))
	}
}

// TestChatImageCacheControlSurvives checks the image branch of the block
// rebuilder preserves cache_control too (the marker is commonly pinned on the
// last block of a large multimodal prefix).
func TestChatImageCacheControlSurvives(t *testing.T) {
	// Real 1x1 PNG as a data: URL — decoded inline, no network. Built with
	// image/png so it survives loadAnthropicImageSource's decode+re-encode.
	pngDataURL := tinyPNGDataURL(t)
	reqJSON := `{
		"model": "anthropic/claude-haiku-4.5",
		"messages": [
			{"role": "user", "content": [
				{"type": "image_url", "image_url": {"url": "` + pngDataURL + `"}, "cache_control": {"type": "ephemeral"}}
			]}
		]
	}`

	var req qtypes.OpenAIChatRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	body, err := adapter.ToAnthropic(&req, "")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	msgs, err := anthropicUpstreamMessages(t.Context(), body)
	if err != nil {
		t.Fatalf("anthropicUpstreamMessages: %v", err)
	}
	cc := firstUserBlockCacheControl(t, msgs)
	if got := cc["type"]; got != "ephemeral" {
		t.Fatalf("image block cache_control.type = %v, want ephemeral", got)
	}
}

// TestChatWithoutCacheControlInjectsNone guards against auto-injecting cache
// breakpoints the client never sent (Anthropic hard-caps at 4 breakpoints, so
// silent injection would burn the client's budget and risk a provider 400).
func TestChatWithoutCacheControlInjectsNone(t *testing.T) {
	const reqJSON = `{
		"model": "anthropic/claude-haiku-4.5",
		"messages": [
			{"role": "user", "content": [{"type": "text", "text": "hello"}]}
		]
	}`

	var req qtypes.OpenAIChatRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	body, err := adapter.ToAnthropic(&req, "")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	msgs, err := anthropicUpstreamMessages(t.Context(), body)
	if err != nil {
		t.Fatalf("anthropicUpstreamMessages: %v", err)
	}
	raw, err := json.Marshal(msgs)
	if err != nil {
		t.Fatalf("marshal messages: %v", err)
	}
	if strings.Contains(string(raw), "cache_control") {
		t.Fatalf("cache_control injected where the client sent none: %s", raw)
	}
}

func tinyPNGDataURL(t *testing.T) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 1, G: 2, B: 3, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func firstUserBlockCacheControl(t *testing.T, msgs []qtypes.AnthropicMessage) map[string]any {
	t.Helper()
	for _, m := range msgs {
		if m.Role != "user" {
			continue
		}
		blocks, ok := m.Content.([]map[string]any)
		if !ok {
			t.Fatalf("user content = %T, want []map[string]any", m.Content)
		}
		if len(blocks) == 0 {
			t.Fatalf("user content has no blocks")
		}
		cc, ok := blocks[0]["cache_control"].(map[string]any)
		if !ok {
			t.Fatalf("first user block is missing cache_control: %#v", blocks[0])
		}
		return cc
	}
	t.Fatalf("no user message present: %#v", msgs)
	return nil
}
