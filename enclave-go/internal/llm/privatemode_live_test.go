//go:build linux && live_provider_wave

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/privatemode"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Runs in the packaged scratch image with its actual vendor proxy. The only
// input is a dedicated test credential; no prompt or response is logged.
func TestLivePrivatemodePackagedStreaming(t *testing.T) {
	key := os.Getenv("PRIVATEMODE_API_KEY")
	if key == "" {
		t.Skip("set PRIVATEMODE_API_KEY for a paid encrypted smoke")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	client, err := privatemode.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ConfigurePrivatemode(client)
	defer ConfigurePrivatemode(nil)
	assertPrivatemodeUnprivileged(t)
	for _, model := range []string{"gpt-oss-120b", "glm-5.3", "glm-5.3-flash"} {
		t.Run(model, func(t *testing.T) { livePrivatemodeModel(t, ctx, key, model) })
	}
}

func livePrivatemodeModel(t *testing.T, ctx context.Context, key, model string) {
	t.Helper()
	maxTokens := 1024
	req := &qtypes.OpenAIChatRequest{Model: model, MaxTokens: &maxTokens, ReasoningEffort: "low"}
	body := &qtypes.AnthropicMessagesRequest{MaxTokens: maxTokens, MaxTokensExplicit: true,
		Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Reply with exactly PONG and nothing else."}}}
	var out bytes.Buffer
	err := newOpenAICompatible("privatemode", key).InvokeStreaming(ctx, req, body, &out,
		InvokeOptions{Provider: "privatemode", UpstreamModel: model, ProviderCacheScope: "isolated-live-probe-workspace"})
	if err != nil {
		t.Fatalf("encrypted stream failed: %v", err)
	}
	input, output := 0, 0
	for _, line := range strings.Split(out.String(), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var event struct {
			Usage struct {
				Input  int `json:"input_tokens"`
				Output int `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) == nil {
			input = max(input, event.Usage.Input)
			output = max(output, event.Usage.Output)
		}
	}
	if input <= 0 || output <= 0 {
		t.Fatalf("missing billable usage input=%d output=%d", input, output)
	}
	visible, err := providerWaveVisibleText(out.Bytes())
	if err != nil || strings.TrimSpace(visible) != "PONG" {
		t.Fatalf("unexpected output: visible_bytes=%d parse_error=%v input=%d output=%d length_stop=%v", len(visible), err, input, output, bytes.Contains(out.Bytes(), []byte(`"stop_reason":"max_tokens"`)))
	}
	t.Logf("encrypted PONG and billable usage verified: input=%d output=%d", input, output)
}

func assertPrivatemodeUnprivileged(t *testing.T) {
	t.Helper()
	files, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		cmd, _ := os.ReadFile(path)
		if !bytes.HasPrefix(cmd, []byte("/privatemode-proxy\x00")) {
			continue
		}
		status, err := os.ReadFile(filepath.Join(filepath.Dir(path), "status"))
		if err != nil || !bytes.Contains(status, []byte("Uid:\t65532\t65532\t65532\t65532")) ||
			!bytes.Contains(status, []byte("Gid:\t65532\t65532\t65532\t65532")) ||
			!bytes.Contains(status, []byte("NoNewPrivs:\t1")) ||
			!bytes.Contains(status, []byte("CapEff:\t0000000000000000")) {
			t.Fatal("proxy privilege isolation failed")
		}
		t.Log("proxy runs as uid/gid 65532, no capabilities, no_new_privs=1")
		return
	}
	t.Fatal("vendor child not found")
}

func TestLivePrivatemodeScopedCache(t *testing.T) {
	key := os.Getenv("PRIVATEMODE_API_KEY")
	if key == "" {
		t.Skip("set PRIVATEMODE_API_KEY for a paid encrypted cache smoke")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	client, err := privatemode.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ConfigurePrivatemode(client)
	defer ConfigurePrivatemode(nil)
	prefix := strings.Repeat("This is synthetic public cache-test data, not a customer conversation.\n", 150)
	req := &qtypes.OpenAIChatRequest{Model: "openai/gpt-oss-120b", ReasoningEffort: "low"}
	body := &qtypes.AnthropicMessagesRequest{MaxTokens: 1024, MaxTokensExplicit: true,
		Messages: []qtypes.AnthropicMessage{{Role: "user", Content: prefix + "\nReply exactly PONG."}}}
	for attempt := 1; attempt <= 3; attempt++ {
		var out bytes.Buffer
		if err := newOpenAICompatible("privatemode", key).InvokeStreaming(ctx, req, body, &out,
			InvokeOptions{Provider: "privatemode", UpstreamModel: "gpt-oss-120b", ProviderCacheScope: "isolated-live-cache-smoke"}); err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(out.String(), "\n") {
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var event struct {
				Usage struct {
					Cached int `json:"cache_read_input_tokens"`
				} `json:"usage"`
			}
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) == nil && event.Usage.Cached > 0 {
				t.Logf("encrypted cached usage verified: attempt=%d cached_tokens=%d", attempt, event.Usage.Cached)
				return
			}
		}
	}
	t.Fatal("no upstream cache hit observed in three bounded attempts")
}
