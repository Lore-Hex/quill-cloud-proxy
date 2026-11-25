package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Match TestProviderHistoryMessagesHandler's net.Pipe and mock transport: no
// listener is needed to exercise the HTTP handler, authorization, and provider.
func TestServeOneMessagesCapturedClaudeCodeSystemRole(t *testing.T) {
	request, err := os.ReadFile("../../internal/adapter/testdata/claude-code-messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var native adapter.AnthropicNativeRequest
	if err := json.Unmarshal(request, &native); err != nil {
		t.Fatal(err)
	}
	wantMessages := []types.AnthropicMessage{
		{Role: "user", Content: []any{
			map[string]any{"type": "text", "text": "U1"},
			map[string]any{"type": "text", "text": "U2"},
			map[string]any{"type": "text", "text": "REMINDER TEXT"},
		}},
		native.Messages[2], native.Messages[3],
	}
	wantShim := &types.OpenAIChatRequest{
		Messages: []types.OpenAIChatMessage{{Role: "system", Content: "S1\n\nS2\n\nS3"}},
		Tools:    adapter.ChatToolsFromAnthropicTools(native.Tools),
	}
	for _, m := range wantMessages {
		wantShim.Messages = append(wantShim.Messages, types.OpenAIChatMessage{Role: m.Role, Content: m.Content})
	}
	wantTokens := trustedrouter.EstimateInputTokens(wantShim)
	withoutReminder := *wantShim
	withoutReminder.Messages = append([]types.OpenAIChatMessage(nil), wantShim.Messages...)
	withoutReminder.Messages[1].Content = wantMessages[0].Content.([]any)[:2]
	if wantTokens <= trustedrouter.EstimateInputTokens(&withoutReminder) {
		t.Fatal("reminder text did not increase token estimate")
	}
	authorizedTokens := make(chan int, 1)
	gateway := trustedrouter.New("http://127.0.0.1", "test-token", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var payload string
		switch r.URL.Path {
		case "/internal/gateway/validate":
			payload = `{"data":{"workspace_id":"ws_system","api_key_hash":"key_system"}}`
		case "/internal/gateway/authorize":
			var body struct {
				EstimatedInputTokens int `json:"estimated_input_tokens"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			authorizedTokens <- body.EstimatedInputTokens
			payload = `{"data":{"authorization_id":"auth_system","workspace_id":"ws_system","api_key_hash":"key_system","model":"anthropic/claude-opus-5.5","endpoint_id":"anthropic/claude-opus-5.5@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`
		case "/internal/gateway/settle":
			payload = `{"data":{"settled":true,"generation_id":"gen_system","cost_microdollars":1,"model":"anthropic/claude-opus-5.5","provider":"anthropic"}}`
		default:
			return nil, fmt.Errorf("unexpected mock control-plane path %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
	})})
	streamer := &fakeStreamingLLM{}
	server, client := net.Pipe()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveOne(context.Background(), server, registryForBearer("system-token"), streamer, nil, nil, gateway, nil)
	}()
	if _, err := fmt.Fprintf(client, "POST /v1/messages?beta=true HTTP/1.1\r\nAuthorization: Bearer system-token\r\nanthropic-version: 2023-06-01\r\nanthropic-beta: claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,thinking-token-count-2026-05-13,advanced-tool-use-2025-11-20,effort-2025-11-24\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(request), request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", response.StatusCode, payload)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	if streamer.body == nil || !reflect.DeepEqual(streamer.body.Messages, wantMessages) {
		t.Fatalf("provider body = %#v, want messages %#v", streamer.body, wantMessages)
	}
	if streamer.request == nil || !reflect.DeepEqual(streamer.request.Messages, wantShim.Messages) {
		t.Fatalf("provider shim = %#v, want messages %#v", streamer.request, wantShim.Messages)
	}
	select {
	case got := <-authorizedTokens:
		if got != wantTokens {
			t.Fatalf("authorized input tokens=%d, want %d including reminder", got, wantTokens)
		}
	default:
		t.Fatal("request was not authorized")
	}
}
