package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

const hostedQuestions = `{
 "refund": {"type":"boolean","instructions":"Is a refund requested?","criteria":{"true":"asks for money back"}},
 "route":  {"type":"choice","instructions":"Route it.","criteria":{"billing":"charges","shipping":"delivery"}},
 "urgency":{"type":"score","instructions":"How urgent?","criteria":["low","high"]}
}`

func hostedRequest(t *testing.T) (*DecideRequest, []decide.Spec) {
	t.Helper()
	var questions map[string]decide.Question
	if err := json.Unmarshal([]byte(hostedQuestions), &questions); err != nil {
		t.Fatal(err)
	}
	specs, err := decide.Parse(questions)
	if err != nil {
		t.Fatal(err)
	}
	return &DecideRequest{Model: "typesafe-ai/jev", State: json.RawMessage(`"charged twice"`), Questions: questions}, specs
}

func hostedServer(t *testing.T, wantPath string, check func(body map[string]any), reply string, status int) *openAICompatibleClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer host-key" {
			t.Errorf("authorization = %q", got)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		if check != nil {
			check(body)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(server.Close)
	return &openAICompatibleClient{baseURL: server.URL, apiKey: "host-key", httpc: server.Client()}
}

func TestInvokeDecideTranslatesTypeSafeSystemOne(t *testing.T) {
	req, specs := hostedRequest(t)
	client := hostedServer(t, "/systemone", func(body map[string]any) {
		// TypeSafe's names on the wire: jev-latest, and "noul" for yes/no.
		if body["model"] != "jev-latest" {
			t.Errorf("model = %v, want the upstream id", body["model"])
		}
		questions, _ := body["questions"].(map[string]any)
		refund, _ := questions["refund"].(map[string]any)
		route, _ := questions["route"].(map[string]any)
		if refund["type"] != "noul" || route["type"] != "choice" {
			t.Errorf("wire types = %v, %v", refund["type"], route["type"])
		}
		if criteria, _ := refund["criteria"].(map[string]any); criteria["true"] != "asks for money back" {
			t.Errorf("criteria not forwarded: %v", refund["criteria"])
		}
	}, `{"model":"jev-1.13","answers":{
	  "refund":{"type":"noul","noul":0.97},
	  "route":{"type":"choice","choice":"billing","probabilities":{"billing":0.96,"shipping":0.04},"confidence":0.93},
	  "urgency":{"type":"score","score":0.8,"legend":{"0":"low","1":"high"},"probabilities":{"0":0.2,"1":0.8},"confidence":0.7}},
	  "usage":{"input_tokens":312,"output_tokens":40}}`, 200)
	client.provider = "typesafe"

	resp, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: "typesafe", UpstreamModel: "jev-latest"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.InputTokens != 312 || resp.OutputTokens != 40 {
		t.Fatalf("snake_case usage not read: %+v", resp)
	}
	// The caller's request must not have been rewritten in place.
	if req.Questions["refund"].Type != decide.TypeBoolean {
		t.Fatal("translating the wire request mutated the caller's question")
	}
	verified, err := decide.Verify(specs, resp.Answers)
	if err != nil {
		t.Fatalf("translated answers fail the public contract: %v", err)
	}
	encoded, _ := json.Marshal(verified["refund"])
	if string(encoded) != `{"type":"boolean","probability":0.97}` {
		t.Fatalf("noul not translated to the public boolean shape: %s", encoded)
	}
	if *verified["route"].Choice != "billing" || *verified["urgency"].Score != 0.8 {
		t.Fatalf("answers = %+v", verified)
	}
}

func TestInvokeDecideSpeaksVercelEvaluate(t *testing.T) {
	req, specs := hostedRequest(t)
	client := hostedServer(t, "/evaluate", func(body map[string]any) {
		questions, _ := body["questions"].(map[string]any)
		refund, _ := questions["refund"].(map[string]any)
		if body["model"] != "typesafe-ai/jev" || refund["type"] != "boolean" {
			t.Errorf("vercel wire body: model=%v type=%v", body["model"], refund["type"])
		}
	}, `{"model":"typesafe-ai/jev","answers":{
	  "refund":{"type":"boolean","probability":0.97},
	  "route":{"type":"choice","choice":"billing","probabilities":{"billing":0.96,"shipping":0.04}},
	  "urgency":{"type":"score","score":0.8,"probabilities":{"0":0.2,"1":0.8}}},
	  "usage":{"inputTokens":312,"outputTokens":40}}`, 200)
	client.provider = "vercel-ai-gateway"

	resp, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: "vercel-ai-gateway", UpstreamModel: "typesafe-ai/jev"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.InputTokens != 312 {
		t.Fatalf("camelCase usage not read: %+v", resp)
	}
	if _, err := decide.Verify(specs, resp.Answers); err != nil {
		t.Fatal(err)
	}
}

func TestInvokeDecideNeverTrustsAHostedAnswer(t *testing.T) {
	// A vendor answer that is well-formed JSON and wrong in substance must reach
	// decide.Verify intact, so that Verify -- not this client -- rejects it.
	req, specs := hostedRequest(t)
	client := hostedServer(t, "/systemone", nil, `{"answers":{
	  "refund":{"type":"noul"},
	  "route":{"type":"choice","choice":"legal","probabilities":{"billing":0.5,"legal":0.5}},
	  "urgency":{"type":"score","score":0.8,"probabilities":{"0":0.2,"1":0.8}}},
	  "usage":{"input_tokens":1}}`, 200)
	client.provider = "typesafe"
	resp, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: "typesafe"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decide.Verify(specs, resp.Answers); err == nil {
		t.Fatal("a missing noul and an undeclared option survived")
	}
}

func TestInvokeDecideSurfacesUpstreamStatusWithoutLeakingIt(t *testing.T) {
	req, _ := hostedRequest(t)
	for _, status := range []int{401, 422, 429, 529} {
		client := hostedServer(t, "/systemone", nil, `{"error":"validation failed for state: charged twice"}`, status)
		client.provider = "typesafe"
		_, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: "typesafe"})
		if err == nil {
			t.Fatalf("status %d returned no error", status)
		}
		got, ok := HTTPStatusFromError(err)
		if !ok || got != status {
			t.Errorf("status %d surfaced as %d (ok=%v); billing classifies refunds by it", status, got, ok)
		}
	}
}

func TestInvokeDecideBoundsTheResponse(t *testing.T) {
	req, _ := hostedRequest(t)
	huge := `{"answers":{},"padding":"` + strings.Repeat("x", maxDecideResponseBytes) + `"}`
	client := hostedServer(t, "/evaluate", nil, huge, 200)
	client.provider = "vercel-ai-gateway"
	if _, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: "vercel-ai-gateway"}); err == nil {
		t.Fatal("an oversized hosted response was accepted")
	}
	noKey := &openAICompatibleClient{provider: "typesafe", baseURL: "https://example.invalid/v1"}
	if _, err := noKey.InvokeDecide(context.Background(), req, InvokeOptions{}); err == nil {
		t.Fatal("a client with no API key made a request")
	}
}
