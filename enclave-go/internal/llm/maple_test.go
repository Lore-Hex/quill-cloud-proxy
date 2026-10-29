package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/maple"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const mapleTestStream = "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":4,\"total_tokens\":104,\"prompt_tokens_details\":{\"cached_tokens\":80}}}\n\ndata: [DONE]\n\n"

func TestMapleEncryptedAdapterPreservesUsage(t *testing.T) {
	var out bytes.Buffer
	err := invokeMapleWith(t.Context(), "synthetic-key", &qtypes.OpenAIChatRequest{Model: "maple/" + maple.Model},
		&qtypes.AnthropicMessagesRequest{MaxTokens: 32, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}}, &out,
		InvokeOptions{Provider: "maple", UpstreamModel: maple.Model, ProviderCacheScope: "authorized-workspace"},
		func(_ context.Context, key, scope string, body []byte) (int, io.ReadCloser, error) {
			if key != "synthetic-key" || scope != "authorized-workspace" {
				t.Fatal("lost managed identity")
			}
			var wire map[string]any
			if json.Unmarshal(body, &wire) != nil || wire["model"] != maple.Model || wire["stream"] != true {
				t.Fatalf("unexpected wire: %s", body)
			}
			return 200, io.NopCloser(strings.NewReader(mapleTestStream)), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	// TR's internal stream carries total input plus its cached subset; the
	// settlement layer, not this translator, subtracts the cached subset.
	for _, want := range []string{"PONG", "\"cache_read_input_tokens\":80", "\"input_tokens\":100", "\"output_tokens\":4", "message_stop"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %s in %s", want, out.String())
		}
	}
}

func TestMapleRefusesUnpinnedAndBYOKBeforeSend(t *testing.T) {
	for _, option := range []InvokeOptions{
		{Provider: "maple", UpstreamModel: maple.Model, ProviderAPIKey: "byok"},
		{Provider: "maple", UpstreamModel: "deepseek-v4-1-flash"},
		{Provider: "openai", UpstreamModel: maple.Model},
	} {
		err := invokeMapleWith(t.Context(), "key", &qtypes.OpenAIChatRequest{}, &qtypes.AnthropicMessagesRequest{}, io.Discard, option,
			func(context.Context, string, string, []byte) (int, io.ReadCloser, error) {
				t.Fatal("unauthorized send")
				return 0, nil, nil
			})
		if err == nil {
			t.Fatal("invalid route accepted")
		}
	}
}

func TestMapleNeverConvertsTruncationOrErrorsToSuccess(t *testing.T) {
	for _, stream := range []string{
		strings.ReplaceAll(mapleTestStream, "data: [DONE]\n\n", ""),
		"data: [DONE]\n\n",
		"data: not-json\n\ndata: [DONE]\n\n",
		"data: {\"error\":{\"message\":\"private upstream data\"}}\n\n",
	} {
		var out bytes.Buffer
		err := invokeMapleWith(t.Context(), "key", &qtypes.OpenAIChatRequest{}, &qtypes.AnthropicMessagesRequest{}, &out,
			InvokeOptions{Provider: "maple", UpstreamModel: maple.Model},
			func(context.Context, string, string, []byte) (int, io.ReadCloser, error) {
				return 200, io.NopCloser(strings.NewReader(stream)), nil
			})
		if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(out.String(), "message_stop") {
			t.Fatalf("err=%v out=%s", err, out.String())
		}
	}
}

func TestMapleFailureIsNotReplayed(t *testing.T) {
	calls := 0
	err := invokeMapleWith(t.Context(), "key", &qtypes.OpenAIChatRequest{}, &qtypes.AnthropicMessagesRequest{}, io.Discard,
		InvokeOptions{Provider: "maple", UpstreamModel: maple.Model},
		func(context.Context, string, string, []byte) (int, io.ReadCloser, error) {
			calls++
			return 0, nil, errors.New("private diagnostic")
		})
	if err == nil || strings.Contains(err.Error(), "private") || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
