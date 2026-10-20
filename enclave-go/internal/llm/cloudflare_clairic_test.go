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

const clairicInput = `{"state":"Invoice INV-2291: total USD 1080.","fields":{"invoice_number":{"type":"text"},"total":{"type":"number"}}}`
const clairicResult = `{"model":"clairic","answers":{"invoice_number":{"type":"text","value":"INV-2291","confidence":0.99},"total":{"type":"number","value":1080}},"truncated":false,"usage":{"input_tokens":308,"output_tokens":0,"passes":2}}`

func clairicRequest(input string) *qtypes.OpenAIChatRequest {
	var req qtypes.OpenAIChatRequest
	raw, _ := json.Marshal(map[string]any{"model": clairicModel, "messages": []map[string]string{{"role": "user", "content": input}}})
	if err := json.Unmarshal(raw, &req); err != nil {
		panic(err)
	}
	return &req
}

func TestClairicNativeExtractionAndExactUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/accounts/test/ai/run/"+clairicUpstream || r.Header.Get("Authorization") != "Bearer operator-key" {
			t.Error("wrong native request")
		}
		for key, value := range map[string]string{"cf-aig-gateway-id": "default", "cf-aig-collect-log": "false", "cf-aig-collect-log-payload": "false", "cf-aig-skip-cache": "true"} {
			if r.Header.Get(key) != value {
				t.Errorf("missing privacy/billing header %s", key)
			}
		}
		var task clairicTask
		if json.NewDecoder(r.Body).Decode(&task) != nil || task.Model != "clairic" || len(task.Fields) != 2 {
			t.Error("wrong native payload")
		}
		fmt.Fprint(w, `{"success":true,"result":`+clairicResult+`}`)
	}))
	defer server.Close()
	client := &openAICompatibleClient{provider: "cloudflare-workers-ai", baseURL: server.URL + "/accounts/test/ai/v1", apiKey: "operator-key", httpc: server.Client()}
	var out bytes.Buffer
	if err := client.InvokeStreaming(t.Context(), clairicRequest(clairicInput), nil, &out, InvokeOptions{UpstreamModel: clairicUpstream, UsageType: "credits"}); err != nil {
		t.Fatal(err)
	}
	result, err := adapter.CollectAnthropicText(bytes.NewReader(out.Bytes()))
	if err != nil || result.Text != clairicResult || result.Usage.InputTokens != 308 || result.Usage.OutputTokens != 0 {
		t.Fatalf("lost native result or metering: %#v %v", result, err)
	}
	var streamed bytes.Buffer
	captured, err := adapter.TransformStreamCaptureWithOptions(bytes.NewReader(out.Bytes()), &streamed, "test", clairicModel, true)
	if err != nil || captured.Usage.InputTokens != 308 || captured.Usage.OutputTokens != 0 || !strings.Contains(streamed.String(), "[DONE]") {
		t.Fatalf("stream lost metering: %v", err)
	}
	if !InputOnlyModel(clairicModel) || InputOnlyModel(clairicModel+"-other") {
		t.Fatal("input-only exception is not exact")
	}
}

func TestClairicRejectsInvalidResultsBeforeOutput(t *testing.T) {
	valid := `{"success":true,"result":` + clairicResult + `}`
	for _, raw := range []string{
		`{"success":false,"errors":[{"message":"private-input"}]}`,
		strings.Replace(valid, `"input_tokens":308`, `"input_tokens":0`, 1),
		strings.Replace(valid, `"input_tokens":308`, `"input_tokens":-1`, 1),
		strings.Replace(valid, `"input_tokens":308`, `"input_tokens":1.5`, 1),
		strings.Replace(valid, `"input_tokens":308`, `"input_tokens":true`, 1),
		strings.Replace(valid, `"input_tokens":308`, `"input_tokens":2147483649`, 1),
		strings.Replace(valid, `"input_tokens":308`, `"other":308`, 1),
		strings.Replace(valid, `"output_tokens":0`, `"output_tokens":10`, 1),
		strings.Replace(valid, `"output_tokens":0`, `"other":0`, 1),
		strings.Replace(valid, `"invoice_number":`, `"wrong_field":`, 1),
		strings.Replace(valid, `"type":"text"`, `"type":"number"`, 1),
		strings.Replace(valid, `"model":"clairic"`, `"model":"other"`, 1),
		strings.Replace(valid, `"value":1080`, `"other":1080`, 1),
		`{"success":true,"success":false,"result":` + clairicResult + `}`,
		`private-input not JSON`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, raw) }))
		client := &openAICompatibleClient{provider: "cloudflare-workers-ai", baseURL: server.URL + "/ai/v1", apiKey: "key", httpc: server.Client()}
		var out bytes.Buffer
		err := client.InvokeStreaming(t.Context(), clairicRequest(clairicInput), nil, &out)
		server.Close()
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "private-input") {
			t.Fatalf("accepted or leaked invalid response: %v", err)
		}
	}
}

func TestClairicRequestValidation(t *testing.T) {
	for _, input := range []string{`null`, `[]`, `Reply PONG`, `{}`, `{"state":"x","fields":{}}`,
		strings.Replace(clairicInput, `"text"`, `"unknown"`, 1),
		strings.Replace(clairicInput, `"state":`, `"model":"other","state":`, 1),
		strings.Replace(clairicInput, `"state":`, `"url":"https://secret.invalid","state":`, 1),
		strings.Replace(clairicInput, `"state":`, `"images":["https://secret.invalid"],"state":`, 1),
		strings.Replace(clairicInput, `"state":`, `"images":["data:image/png;base64,not-base64"],"state":`, 1),
		strings.Replace(clairicInput, `"state":`, `"images":[{"content_type":"text/html","base64":"YQ=="}],"state":`, 1),
		clairicInput + ` {}`, strings.Replace(clairicInput, `"state":`, `"state":"duplicate","state":`, 1),
	} {
		if _, err := clairicPayload(clairicRequest(input)); err == nil {
			t.Errorf("accepted invalid input %s", input)
		}
	}
	req := clairicRequest(clairicInput)
	req.Messages = append(req.Messages, req.Messages[0])
	if _, err := clairicPayload(req); err == nil {
		t.Fatal("accepted chat history")
	}
	req = clairicRequest(clairicInput)
	req.ResponseFormat = map[string]any{"type": "json_object"}
	if _, err := clairicPayload(req); err == nil {
		t.Fatal("accepted response_format")
	}
	for _, kind := range []string{"text", "number", "date", "time", "datetime", "duration", "list", "estimate", "forecast"} {
		input := `{"state":"x","fields":{"answer":{"type":"` + kind + `","items":"text","min":0,"max":100,"horizon":2,"step":1}}}`
		if _, err := clairicPayload(clairicRequest(input)); err != nil {
			t.Errorf("rejected field type %s: %v", kind, err)
		}
	}
}

func TestClairicBlocksRedirectsAndBYOK(t *testing.T) {
	destinationCalls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls++ }))
	defer destination.Close()
	for _, status := range []int{302, 401, 429, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", destination.URL)
			w.WriteHeader(status)
			fmt.Fprint(w, "private-input")
		}))
		client := &openAICompatibleClient{provider: "cloudflare-workers-ai", baseURL: server.URL + "/ai/v1", apiKey: "key", httpc: server.Client()}
		var out bytes.Buffer
		err := client.InvokeStreaming(t.Context(), clairicRequest(clairicInput), nil, &out)
		if err == nil || strings.Contains(err.Error(), "private-input") || out.Len() != 0 {
			t.Fatal("bad error contract")
		}
		err = client.InvokeStreaming(t.Context(), clairicRequest(clairicInput), nil, &out, InvokeOptions{UsageType: "byok", ProviderAPIKey: "caller"})
		if err == nil || !strings.Contains(err.Error(), "credits") {
			t.Fatal("BYOK accepted")
		}
		server.Close()
	}
	if destinationCalls != 0 {
		t.Fatal("forwarded credential on redirect")
	}
}

func TestClairicLive(t *testing.T) {
	key, account := os.Getenv("CLOUDFLARE_WORKERS_AI_API_TOKEN"), os.Getenv("CLOUDFLARE_WORKERS_AI_ACCOUNT_ID")
	if os.Getenv("TR_LIVE_CLAIRIC") != "1" || key == "" || account == "" {
		t.Skip("explicit synthetic live probe only")
	}
	client := &openAICompatibleClient{provider: "cloudflare-workers-ai", baseURL: "https://api.cloudflare.com/client/v4/accounts/" + account + "/ai/v1", apiKey: key, httpc: &http.Client{Timeout: 60 * time.Second}}
	var out bytes.Buffer
	if err := client.InvokeStreaming(t.Context(), clairicRequest(clairicInput), nil, &out); err != nil {
		t.Fatal(err)
	}
	result, err := adapter.CollectAnthropicText(bytes.NewReader(out.Bytes()))
	if err != nil || result.Usage.InputTokens <= 0 || result.Usage.OutputTokens != 0 {
		t.Fatal("invalid live usage")
	}
	var payload struct {
		Answers map[string]struct {
			Value any `json:"value"`
		} `json:"answers"`
	}
	if json.Unmarshal([]byte(result.Text), &payload) != nil || payload.Answers["invoice_number"].Value != "INV-2291" || payload.Answers["total"].Value != float64(1080) {
		t.Fatal("live extraction wrong")
	}
	t.Logf("live native extraction passed: input_tokens=%d output_tokens=%d", result.Usage.InputTokens, result.Usage.OutputTokens)
}
