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

// secretState is the caller's content. It is what no error may carry: a vendor
// quotes the request it rejects, and a decoder quotes the literal it choked on.
const secretState = "PRIVATE-STATE charged twice"

// assertContentFree fails if err could put request or response content in a
// log: it must be a *DecideError, its class must come from the closed
// vocabulary, and neither its text nor its class may hold any of `forbidden`.
func assertContentFree(t *testing.T, label string, err error, wantClass string, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: no error", label)
	}
	failed, ok := err.(*DecideError)
	if !ok {
		t.Fatalf("%s: error is %T, want *DecideError (anything else may hold upstream text)", label, err)
	}
	if failed.Class != wantClass {
		t.Fatalf("%s: class = %q, want %q", label, failed.Class, wantClass)
	}
	for _, secret := range forbidden {
		for _, surface := range []string{err.Error(), DecideErrorClass(err)} {
			if strings.Contains(surface, secret) {
				t.Fatalf("%s: %q leaked into %q", label, secret, surface)
			}
		}
	}
}

func TestInvokeDecideSurfacesUpstreamStatusWithoutLeakingIt(t *testing.T) {
	req, _ := hostedRequest(t)
	echo := `{"error":"validation failed for state: ` + secretState + `"}`
	// 201 is here on purpose: not an error status, not a 200, and its body is
	// dropped like the rest.
	for _, status := range []int{201, 401, 422, 429, 529} {
		client := hostedServer(t, "/systemone", nil, echo, status)
		client.provider = "typesafe"
		_, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: "typesafe"})
		assertContentFree(t, http.StatusText(status), err, DecideErrHTTP, secretState, "validation failed")
		got, ok := DecideErrorStatus(err)
		if !ok || got != status {
			t.Errorf("status %d surfaced as %d (ok=%v); billing classifies refunds by it", status, got, ok)
		}
	}
}

func TestInvokeDecideDecodeFailuresCarryNoContent(t *testing.T) {
	req, _ := hostedRequest(t)
	for label, tc := range map[string]struct {
		path, provider, body, class string
	}{
		// encoding/json quotes the literal it cannot fit into a float64.
		"relay number overflow":  {"/evaluate", "vercel-ai-gateway", `{"answers":{"refund":{"type":"boolean","probability":1e999931337}}}`, DecideErrDecode},
		"vendor number overflow": {"/systemone", "typesafe", `{"answers":{"refund":{"type":"noul","noul":1e999931337}}}`, DecideErrDecode},
		"vendor wrong shape":     {"/systemone", "typesafe", `{"answers":"` + secretState + `"}`, DecideErrDecode},
		"relay truncated":        {"/evaluate", "vercel-ai-gateway", `{"answers":{"refund":{"type":"boolean","probability":0.9`, DecideErrDecode},
		// Go keeps the LAST of two equal keys without a word: 0.9 here.
		"relay duplicate answer":  {"/evaluate", "vercel-ai-gateway", `{"answers":{"refund":{"type":"boolean","probability":0.1},"refund":{"type":"boolean","probability":0.9}}}`, DecideErrDuplicate},
		"vendor duplicate option": {"/systemone", "typesafe", `{"answers":{"route":{"type":"choice","choice":"billing","probabilities":{"billing":0.1,"billing":0.9,"shipping":0.1}}}}`, DecideErrDuplicate},
	} {
		client := hostedServer(t, tc.path, nil, tc.body, 200)
		client.provider = tc.provider
		_, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: tc.provider})
		assertContentFree(t, label, err, tc.class, secretState, "999931337", "billing")
	}
}

func TestTypeSafeAnswerThatSaysTwoThingsReachesVerifyIntact(t *testing.T) {
	req, specs := hostedRequest(t)
	// A "noul" that also carries a score and a choice. Translation used to keep
	// only the noul, handing Verify a clean boolean it had no reason to refuse.
	client := hostedServer(t, "/systemone", nil, `{"answers":{
	  "refund":{"type":"noul","noul":0.9,"score":0.1,"choice":"x","probabilities":{"x":1}},
	  "route":{"type":"choice","choice":"billing","confidence":0.8,"probabilities":{"billing":0.9,"shipping":0.1}},
	  "urgency":{"type":"score","score":0.8,"confidence":0.7,"legend":{"0":"low","1":"high"},"probabilities":{"0":0.2,"1":0.8}}},
	  "usage":{"input_tokens":12,"output_tokens":null}}`, 200)
	client.provider = "typesafe"
	resp, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: "typesafe"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = decide.Verify(specs, resp.Answers)
	if got := decide.ViolationKind(err); got != decide.KindType {
		t.Fatalf("kind = %q (%v), want %q", got, err, decide.KindType)
	}
}

func TestInvokeDecideReportsCancellationAsItsOwnClass(t *testing.T) {
	req, _ := hostedRequest(t)
	client := hostedServer(t, "/systemone", nil, `{}`, 200)
	client.provider = "typesafe"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.InvokeDecide(ctx, req, InvokeOptions{Provider: "typesafe"})
	assertContentFree(t, "cancelled before the call", err, DecideErrCanceled)
}

func TestDecideErrorClassNeverReturnsForeignText(t *testing.T) {
	if got := DecideErrorClass(io.ErrUnexpectedEOF); got != "unknown" {
		t.Fatalf("class of a foreign error = %q, want unknown", got)
	}
	if got := DecideErrorClass(&upstreamHTTPError{status: 422, body: secretState}); got != "unknown" {
		t.Fatalf("class of a body-carrying error = %q, want unknown", got)
	}
}

func TestInvokeDecideBoundsTheResponse(t *testing.T) {
	req, _ := hostedRequest(t)
	huge := `{"answers":{},"padding":"` + strings.Repeat("x", maxDecideResponseBytes) + `"}`
	client := hostedServer(t, "/evaluate", nil, huge, 200)
	client.provider = "vercel-ai-gateway"
	_, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: "vercel-ai-gateway"})
	assertContentFree(t, "oversized hosted response", err, DecideErrTooLarge)
	noKey := &openAICompatibleClient{provider: "typesafe", baseURL: "https://example.invalid/v1"}
	_, err = noKey.InvokeDecide(context.Background(), req, InvokeOptions{})
	assertContentFree(t, "client with no API key", err, DecideErrConfig)
}
