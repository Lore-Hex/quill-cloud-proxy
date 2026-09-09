package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var scaleDownTestInputs = map[string]string{
	"compress":  `{"context":"Acme launched Monday. Feedback is reviewed Friday.","prompt":"When is feedback reviewed?","scaledown":{"rate":"auto"}}`,
	"summarize": `{"text":"Acme launched Monday. Feedback is reviewed Friday.","instructions":"One short sentence.","max_tokens":64}`,
	"extract":   `{"text":"Acme launched Monday.","entities":{"company":"The company name"}}`,
	"classify":  `{"text":"My invoice has incorrect tax.","labels":[{"name":"billing","rubric":"Is this about an invoice?"},{"name":"technical","rubric":"Is this about software?"}]}`,
}

func scaleDownRequest(task, input string) *qtypes.OpenAIChatRequest {
	var req qtypes.OpenAIChatRequest
	raw, _ := json.Marshal(map[string]any{"model": "scaledown/" + task, "messages": []map[string]string{{"role": "user", "content": input}}})
	if err := json.Unmarshal(raw, &req); err != nil {
		panic(err)
	}
	return &req
}

func TestScaleDownNativeTasksAndExactUsage(t *testing.T) {
	results := map[string]string{
		"compress":  `"successful":true,"results":{"success":true,"compressed_prompt":"Friday"}`,
		"summarize": `"summary":"Acme will review feedback Friday."`,
		"extract":   `"entities":[]`,
		"classify":  `"top_label":"billing","results":[{"id":"0","top_label":"billing"}]`,
	}
	for task, input := range scaleDownTestInputs {
		t.Run(task, func(t *testing.T) {
			response := `{"input_tokens":170,` + results[task] + `}`
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "POST" || r.URL.Path != scaleDownPaths[task] || r.Header.Get("x-api-key") != "operator-key" || r.Header.Get("Authorization") != "" {
					t.Errorf("invalid native request shape")
				}
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				if _, ok := payload["messages"]; ok {
					t.Error("OpenAI payload reached native endpoint")
				}
				fmt.Fprint(w, response)
			}))
			defer server.Close()
			client := &openAICompatibleClient{provider: "scaledown", baseURL: server.URL, apiKey: "operator-key", httpc: server.Client()}
			var out bytes.Buffer
			err := client.InvokeStreaming(t.Context(), scaleDownRequest(task, input), nil, &out, InvokeOptions{Provider: "scaledown", UpstreamModel: task, UsageType: "credits"})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || !strings.Contains(out.String(), `"input_tokens":170`) || !strings.Contains(out.String(), `"output_tokens":0`) || !strings.Contains(out.String(), `message_stop`) {
				t.Fatalf("incomplete or inexact usage stream: %s", out.String())
			}
			if strings.Contains(out.String(), "operator-key") {
				t.Fatal("credential in output")
			}
			result, err := adapter.CollectAnthropicText(bytes.NewReader(out.Bytes()))
			if err != nil || result.Text != response || result.Usage.InputTokens != 170 || result.Usage.OutputTokens != 0 {
				t.Fatalf("buffered adapter lost native usage/result: %#v %v", result, err)
			}
			var streamed bytes.Buffer
			captured, err := adapter.TransformStreamCaptureWithOptions(bytes.NewReader(out.Bytes()), &streamed, "test", "scaledown/"+task, true)
			if err != nil || captured.Usage.InputTokens != 170 || captured.Usage.OutputTokens != 0 || !strings.Contains(streamed.String(), "[DONE]") {
				t.Fatalf("OpenAI stream lost native usage: %#v %v", captured, err)
			}
		})
	}
}

func TestScaleDownRejectsInvalidUsageAndResultsBeforeOutput(t *testing.T) {
	for _, body := range []string{
		`{"summary":"hi"}`, `{"input_tokens":0,"summary":"hi"}`, `{"input_tokens":-1,"summary":"hi"}`,
		`{"input_tokens":true,"summary":"hi"}`, `{"input_tokens":1.5,"summary":"hi"}`,
		`{"input_tokens":2147483649,"summary":"hi"}`, `{"input_tokens":12,"summary":""}`,
		`{"input_tokens":12,"error":"secret echoed"}`, `not JSON`,
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer server.Close()
			client := &openAICompatibleClient{provider: "scaledown", baseURL: server.URL, apiKey: "key", httpc: server.Client()}
			var out bytes.Buffer
			err := client.InvokeStreaming(t.Context(), scaleDownRequest("summarize", "Some text"), nil, &out)
			if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "secret echoed") {
				t.Fatalf("invalid response emitted: %v %s", err, out.String())
			}
		})
	}
}

func TestScaleDownErrorsRedactedAndRedirectsBlocked(t *testing.T) {
	for _, status := range []int{302, 400, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			targetCalls := 0
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls++ }))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
				fmt.Fprint(w, "secret and user prompt")
			}))
			defer server.Close()
			client := &openAICompatibleClient{provider: "scaledown", baseURL: server.URL, apiKey: "secret", httpc: server.Client()}
			var out bytes.Buffer
			err := client.InvokeStreaming(t.Context(), scaleDownRequest("summarize", "text"), nil, &out)
			upstream, ok := err.(*upstreamHTTPError)
			if !ok || upstream.status != status || targetCalls != 0 || out.Len() != 0 || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe error/redirect: %v", err)
			}
		})
	}
}

func TestScaleDownRequestValidation(t *testing.T) {
	for _, tc := range []struct{ task, input string }{
		{"unknown", "text"}, {"extract", `{"text":"x","entities":{}}`},
		{"compress", `{"context":"x"}`}, {"compress", `{"context":"x","prompt":"y","url":"http://localhost"}`},
		{"summarize", `{"text":"x","max_tokens":0}`}, {"summarize", `{"text":"x","max_tokens":20049}`},
		{"classify", `{"text":"x","labels":[{"name":"a","rubric":"x"},{"name":"a","rubric":"y"}]}`},
		{"summarize", ""},
	} {
		if _, err := scaleDownPayload(scaleDownRequest(tc.task, tc.input), tc.task); err == nil {
			t.Errorf("accepted invalid request %s %s", tc.task, tc.input)
		}
	}
	req := scaleDownRequest("summarize", `{"text":"x","max_tokens":128}`)
	limit := 16
	req.MaxTokens = &limit
	raw, err := scaleDownPayload(req, "summarize")
	if err != nil || !strings.Contains(string(raw), `"max_tokens":16`) {
		t.Fatalf("outer cap not honored: %s %v", raw, err)
	}
	for _, raw := range []string{
		`{"messages":[{"role":"user","content":"x"}],"tools":[{"type":"function","function":{"name":"test"}}]}`,
		`{"messages":[{"role":"user","content":"x"}],"response_format":{"type":"json_object"}}`,
		`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com"}}]}]}`,
		`{"messages":[{"role":"assistant","content":"prior"},{"role":"user","content":"x"}]}`,
	} {
		var r qtypes.OpenAIChatRequest
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			t.Fatal(err)
		}
		if _, err := scaleDownPayload(&r, "summarize"); err == nil {
			t.Errorf("accepted unsupported request: %s", raw)
		}
	}
	client := &openAICompatibleClient{provider: "scaledown"}
	for _, opts := range []InvokeOptions{{UsageType: "byok"}, {ProviderAPIKey: "caller-key"}} {
		if err := client.InvokeStreaming(t.Context(), req, nil, &bytes.Buffer{}, opts); err == nil {
			t.Fatal("accepted BYOK")
		}
	}
}

func TestScaleDownLive(t *testing.T) {
	if os.Getenv("SCALEDOWN_LIVE_TEST") != "1" {
		t.Skip("opt-in synthetic native adapter smoke")
	}
	key := os.Getenv("SCALEDOWN_API_KEY")
	if key == "" {
		t.Fatal("missing test credential")
	}
	client := &openAICompatibleClient{provider: "scaledown", baseURL: "https://api.scaledown.xyz", apiKey: key, httpc: &http.Client{Timeout: 45 * time.Second}}
	for task, input := range scaleDownTestInputs {
		t.Run(task, func(t *testing.T) {
			var out bytes.Buffer
			if err := client.InvokeStreaming(t.Context(), scaleDownRequest(task, input), nil, &out, InvokeOptions{UpstreamModel: task, UsageType: "credits"}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), `message_stop`) || !strings.Contains(out.String(), `"output_tokens":0`) {
				t.Fatal("incomplete native result")
			}
		})
	}
}
