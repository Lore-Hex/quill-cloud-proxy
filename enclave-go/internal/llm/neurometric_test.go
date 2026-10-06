package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const decisionFixture = `{"type":"choice","answer":"billing","confidence":0.9804957659010405,"probabilities":{"billing":0.9968459959095745,"technical":0.0031353313672464536,"sales":1.867272317912584e-05}}`
const decisionCompletionFixture = `{"choices":[{"message":{"role":"assistant","content":"{\"answer\":\"billing\"}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":167,"completion_tokens":0,"total_tokens":167},"decision":` + decisionFixture + `,"provider_usage":{"cost_microdollars":999999},"internal_secret":"do-not-forward"}`

func TestNeurometricDecisionUsesOneJSONCallForBothClientModes(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			calls := 0
			httpc := &http.Client{Transport: byokRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				var payload map[string]any
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if payload["stream"] != false || payload["stream_options"] != nil || payload["model"] != "neurometric/structured-decisions" {
					t.Fatalf("unexpected upstream request: %#v", payload)
				}
				if req.Header.Get("Accept") != "application/json" || req.Header.Get("Authorization") != "Bearer test-key" {
					t.Fatal("missing JSON negotiation or authentication")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(decisionCompletionFixture))}, nil
			})}
			req := &qtypes.OpenAIChatRequest{Model: "neurometric/structured-decisions", Stream: stream}
			var native bytes.Buffer
			err := invokeOpenAICompatibleStreamingWithClient(t.Context(), httpc, "neurometric", "https://wharf.neurometric.ai/v1", "test-key", req,
				&qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Synthetic classification"}}}, &native, req.Model)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || req.Stream != stream {
				t.Fatalf("calls=%d caller stream=%t", calls, req.Stream)
			}
			for _, forbidden := range []string{"do-not-forward", "cost_microdollars"} {
				if strings.Contains(native.String(), forbidden) {
					t.Fatalf("unexpected provider field forwarded: %s", forbidden)
				}
			}
			assertDecisionChatRoundTrip(t, native.String(), stream)
		})
	}
}

func assertDecisionChatRoundTrip(t *testing.T, native string, stream bool) {
	t.Helper()
	var out bytes.Buffer
	var result adapter.StreamResult
	var err error
	if stream {
		result, err = adapter.TransformStreamCaptureWithOptions(strings.NewReader(native), &out, "chat_test", "neurometric/structured-decisions", true)
	} else {
		result, err = adapter.CollectAnthropicText(strings.NewReader(native))
		if err == nil {
			err = adapter.WriteChatCompletionResponseWithProviderMetadata(&out, "chat_test", "neurometric/structured-decisions", result.Text, "", result.ToolCalls,
				result.Usage.InputTokens, result.Usage.OutputTokens, result.Usage, 123, result.FinishReason, result.Citations, result.SearchResults, result.Decision)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal([]byte(decisionFixture), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Decision, want) || result.Text != `{"answer":"billing"}` {
		t.Fatalf("decision/text changed: %#v %q", result.Decision, result.Text)
	}
	// The provider's zero completion tokens remain authoritative at the
	// adapter boundary; decision labels/scores are never counted as output.
	if result.Usage == nil || result.Usage.InputTokens != 167 || result.Usage.OutputTokens != 0 {
		t.Fatalf("usage changed: %#v", result.Usage)
	}
	var payload map[string]any
	if stream {
		count := 0
		for _, line := range strings.Split(out.String(), "\n") {
			if !strings.HasPrefix(line, "data: {") {
				continue
			}
			var chunk map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &chunk); err != nil {
				t.Fatal(err)
			}
			if _, ok := chunk["decision"]; ok {
				count++
				payload = chunk
			}
		}
		if count != 1 || strings.Index(out.String(), `"decision"`) > strings.Index(out.String(), `"finish_reason":"stop"`) || !strings.HasSuffix(out.String(), "data: [DONE]\n\n") {
			t.Fatalf("invalid decision chunk placement/count: %s", out.String())
		}
	} else if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload["decision"], want) {
		t.Fatalf("public decision changed: %#v", payload["decision"])
	}
}

func TestOtherNeurometricModelsKeepStreaming(t *testing.T) {
	httpc := &http.Client{Transport: byokRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		var payload map[string]any
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["stream"] != true || payload["stream_options"] == nil || req.Header.Get("Accept") != "text/event-stream" {
			t.Fatalf("ordinary model stopped streaming: %#v", payload)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"))}, nil
	})}
	err := invokeOpenAICompatibleStreamingWithClient(t.Context(), httpc, "neurometric", "https://wharf.neurometric.ai/v1", "test-key",
		&qtypes.OpenAIChatRequest{Model: "neurometric/conversation-summary"}, &qtypes.AnthropicMessagesRequest{}, io.Discard, "neurometric/conversation-summary")
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpenAICompletionRejectsInvalidUpstreamBeforeOutput(t *testing.T) {
	for _, body := range []string{
		`not json`, `null`, `{"choices":[]}`, `{"choices":[{"message":{},"finish_reason":null}]}`,
		`{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}`,
		strings.Replace(decisionCompletionFixture, `"prompt_tokens":167`, `"prompt_tokens":0`, 1),
		strings.Replace(decisionCompletionFixture, `"completion_tokens":0`, `"completion_tokens":-1`, 1),
		strings.Replace(decisionCompletionFixture, `"message":{"role":"assistant","content":"{\"answer\":\"billing\"}"}`, `"message":{"content":[]}`, 1),
		`{"error":{"message":"private-upstream-error"},"choices":[]}`,
		decisionCompletionFixture + `{}`, strings.Repeat("x", (1<<20)+1),
	} {
		var out bytes.Buffer
		err := translateOpenAICompletionToAnthropic(strings.NewReader(body), &out, "neurometric")
		status, ok := HTTPStatusFromError(err)
		if !ok || status != 502 || out.Len() != 0 || strings.Contains(err.Error(), "private-upstream-error") {
			t.Fatalf("expected safe 502 without partial output, got %v, bytes=%d", err, out.Len())
		}
	}
}

func TestDecisionStreamMetadataIsBoundedAndProviderScoped(t *testing.T) {
	for _, tc := range []struct {
		name, provider, decision string
		want                     bool
	}{
		{"valid", "neurometric", decisionFixture, true},
		{"nested", "neurometric", `{"levels":[{"answer":"billing","confidence":0.9}],"score":0.5}`, true},
		{"empty", "neurometric", `{}`, true},
		{"null", "neurometric", `null`, false},
		{"array", "neurometric", `[]`, false},
		{"string", "neurometric", `"not-an-object"`, false},
		{"too-large", "neurometric", `{"label":"` + strings.Repeat("a", 64*1024) + `"}`, false},
		{"unrelated-provider", "openai", decisionFixture, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := `data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}` + "\n\n" +
				`data: {"choices":[],"decision":` + tc.decision + `,"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}` + "\n\ndata: [DONE]\n\n"
			var native bytes.Buffer
			if err := translateOpenAIStreamToAnthropicForProvider(strings.NewReader(stream), &native, tc.provider); err != nil {
				t.Fatal(err)
			}
			for _, includeUsage := range []bool{false, true} {
				var out bytes.Buffer
				result, err := adapter.TransformStreamCaptureWithOptions(strings.NewReader(native.String()), &out, "chat_test", "model", includeUsage)
				if err != nil || (result.Decision != nil) != tc.want || strings.Contains(out.String(), `"decision"`) != tc.want {
					t.Fatalf("decision=%#v err=%v stream=%s", result.Decision, err, out.String())
				}
				if result.Text != "ok" || result.Usage == nil || result.Usage.InputTokens != 5 || result.Usage.OutputTokens != 1 {
					t.Fatalf("answer/usage lost: %#v", result)
				}
			}
		})
	}
}
