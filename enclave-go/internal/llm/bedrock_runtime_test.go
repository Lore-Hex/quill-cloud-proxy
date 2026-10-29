//go:build llm_multi

package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

func runtimeReply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestBedrockRuntimeRetentionFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"inherit", 200, `{"mode":"inherit"}`},
		{"unknown", 200, `{"mode":"modified"}`},
		{"missing", 200, `{}`},
		{"forbidden", 403, `{"message":"sensitive upstream diagnostic"}`},
		{"malformed", 200, `{`},
		{"second_json", 200, `{"mode":"none"}{}`},
		{"oversized", 200, `{"mode":"none"}` + strings.Repeat(" ", 4096) + `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := newBedrockRuntimeWithHTTP("test-key", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/data-retention" {
					t.Fatalf("unexpected inference: %s", r.URL)
				}
				if calls == 2 {
					return runtimeReply(tc.status, tc.body), nil
				}
				return runtimeReply(200, `{"mode":"none"}`), nil
			})})
			var out bytes.Buffer
			err := client.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "anthropic/claude-haiku-5.5"}, &qtypes.AnthropicMessagesRequest{MaxTokens: 16}, &out, InvokeOptions{UpstreamModel: "us.anthropic.claude-haiku-5-5"})
			if err == nil || calls != 2 || out.Len() != 0 || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("must stop before inference: %v calls=%d", err, calls)
			}
		})
	}
}

func TestBedrockRuntimeExactProfilesNoReplayAndUsage(t *testing.T) {
	for canonical, native := range bedrockRuntimeModels {
		t.Run(canonical, func(t *testing.T) {
			var hosts []string
			invokes := 0
			client := newBedrockRuntimeWithHTTP("test-key", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer test-key" {
					t.Fatal("wrong credential path")
				}
				if r.Method == "GET" {
					hosts = append(hosts, r.URL.Host)
					return runtimeReply(200, `{"mode":"none"}`), nil
				}
				invokes++
				if r.URL.Host != "bedrock-runtime.us-east-1.amazonaws.com" || r.URL.Path != "/model/"+native+"/invoke-with-response-stream" {
					t.Fatalf("not exact runtime profile: %s", r.URL)
				}
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if payload["anthropic_version"] != "bedrock-2023-05-31" || payload["model"] != nil || payload["max_tokens"] != float64(32) {
					t.Fatalf("wrong native shape: %#v", payload)
				}
				var stream bytes.Buffer
				encoder := eventstream.NewEncoder()
				for _, event := range []string{
					`{"type":"message_start","message":{"id":"test","type":"message","role":"assistant","content":[],"usage":{"input_tokens":4,"output_tokens":0,"cache_read_input_tokens":8,"cache_creation_input_tokens":2}}}`,
					`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"PONG"}}`,
					`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`,
					`{"type":"message_stop"}`,
				} {
					var headers eventstream.Headers
					headers.Set(":message-type", eventstream.StringValue("event"))
					headers.Set(":event-type", eventstream.StringValue("chunk"))
					headers.Set(":content-type", eventstream.StringValue("application/json"))
					wire, _ := json.Marshal(map[string][]byte{"bytes": []byte(event)})
					if err := encoder.Encode(&stream, eventstream.Message{Headers: headers, Payload: wire}); err != nil {
						t.Fatal(err)
					}
				}
				response := runtimeReply(200, stream.String())
				response.Header.Set("Content-Type", "application/vnd.amazon.eventstream")
				return response, nil
			})})
			var out bytes.Buffer
			err := client.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: canonical}, &qtypes.AnthropicMessagesRequest{MaxTokens: 32, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}}, &out, InvokeOptions{UpstreamModel: native})
			if err != nil {
				t.Fatal(err)
			}
			if invokes != 1 || !reflect.DeepEqual(hosts, []string{"bedrock.us-east-1.amazonaws.com", "bedrock.us-east-2.amazonaws.com", "bedrock.us-west-2.amazonaws.com"}) {
				t.Fatalf("retention/dispatch calls: %v %d", hosts, invokes)
			}
			for _, want := range []string{"PONG", `"cache_read_input_tokens":8`, `"cache_creation_input_tokens":2`, "message_stop"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("lost %s in %s", want, &out)
				}
			}
		})
	}
}

func TestBedrockRuntimeRejectsUnapprovedInputBeforeNetwork(t *testing.T) {
	for _, tc := range []struct{ model, upstream, key, tier string }{
		{"anthropic/claude-haiku-5.5", "global.anthropic.claude-haiku-5-5", "", ""},
		{"anthropic/claude-haiku-5.5", "us.anthropic.claude-opus-5-5", "", ""},
		{"unknown", "us.anthropic.claude-haiku-5-5", "", ""},
		{"anthropic/claude-haiku-5.5", "us.anthropic.claude-haiku-5-5", "byok", ""},
		{"anthropic/claude-haiku-5.5", "us.anthropic.claude-haiku-5-5", "", "priority"},
	} {
		client := newBedrockRuntimeWithHTTP("test-key", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network call"); return nil, nil })})
		err := client.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: tc.model, ServiceTier: tc.tier}, &qtypes.AnthropicMessagesRequest{}, io.Discard, InvokeOptions{UpstreamModel: tc.upstream, ProviderAPIKey: tc.key})
		if err == nil {
			t.Fatalf("accepted unapproved input: %+v", tc)
		}
	}
}

func TestBedrockRuntimeWithholdsTerminalOnDamagedOrExtraFrames(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events []string
		damage bool
	}{
		{"missing-stop", []string{`{"type":"message_delta","usage":{"output_tokens":1}}`}, false},
		{"extra-after-stop", []string{`{"type":"message_stop"}`, `{"type":"message_delta","usage":{"output_tokens":1}}`}, false},
		{"malformed", []string{`{"type":"message_stop"}`, `private diagnostic`}, false},
		{"crc-after-stop", []string{`{"type":"message_stop"}`, `{"type":"message_stop"}`}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stream bytes.Buffer
			for _, event := range tc.events {
				var headers eventstream.Headers
				headers.Set(":message-type", eventstream.StringValue("event"))
				headers.Set(":event-type", eventstream.StringValue("chunk"))
				headers.Set(":content-type", eventstream.StringValue("application/json"))
				wire, _ := json.Marshal(map[string][]byte{"bytes": []byte(event)})
				if err := eventstream.NewEncoder().Encode(&stream, eventstream.Message{Headers: headers, Payload: wire}); err != nil {
					t.Fatal(err)
				}
			}
			data := stream.Bytes()
			if tc.damage {
				data[len(data)-1] ^= 0xff
			}
			calls := 0
			client := newBedrockRuntimeWithHTTP("key", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodGet {
					return runtimeReply(200, `{"mode":"none"}`), nil
				}
				calls++
				response := runtimeReply(200, string(data))
				response.Header.Set("Content-Type", "application/vnd.amazon.eventstream")
				return response, nil
			})})
			var out bytes.Buffer
			err := client.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "anthropic/claude-haiku-5.5"}, &qtypes.AnthropicMessagesRequest{MaxTokens: 16}, &out, InvokeOptions{UpstreamModel: "us.anthropic.claude-haiku-5-5"})
			if err == nil || calls != 1 || strings.Contains(out.String(), "message_stop") || strings.Contains(err.Error(), "private diagnostic") {
				t.Fatalf("calls=%d err=%v out=%s", calls, err, out.String())
			}
		})
	}
}

func TestBedrockRuntimeDoesNotReplayHTTPFailure(t *testing.T) {
	calls := 0
	client := newBedrockRuntimeWithHTTP("key", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			return runtimeReply(200, `{"mode":"none"}`), nil
		}
		calls++
		return runtimeReply(503, `{"message":"private diagnostic"}`), nil
	})})
	err := client.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "anthropic/claude-haiku-5.5"}, &qtypes.AnthropicMessagesRequest{MaxTokens: 16}, io.Discard, InvokeOptions{UpstreamModel: "us.anthropic.claude-haiku-5-5"})
	status, ok := HTTPStatusFromError(err)
	if err == nil || calls != 1 || strings.Contains(err.Error(), "private") || !ok || status != 503 {
		t.Fatalf("calls=%d status=%d err=%v", calls, status, err)
	}
}
