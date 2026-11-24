//go:build llm_multi

package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func vertexToolRequest() *qtypes.OpenAIChatRequest {
	return &qtypes.OpenAIChatRequest{
		Model: "google/gemini-4-argon", Stream: true,
		Tools: []any{map[string]any{"type": "function", "function": map[string]any{"name": "lookup"}}},
	}
}

func TestVertexStreamArgsScope(t *testing.T) {
	for _, tc := range []struct {
		model         string
		stream, tools bool
		choice        any
		want          bool
		mode          string
	}{
		{"gemini-4-argon", true, true, nil, true, ""},
		{"gemini-3-flash-preview", true, true, "auto", true, "AUTO"},
		{"gemini-3.1-pro-preview", true, true, "required", true, "ANY"},
		{"gemini-4-argon", true, true, "none", false, "NONE"},
		{"gemini-4-argon", false, true, nil, false, ""},
		{"gemini-4-argon", true, false, nil, false, ""},
		{"gemini-2.5-pro", true, true, nil, false, ""},
		{"gemini-3.1-flash-lite-preview", true, true, nil, false, ""},
		{"gemini-3.1-flash-lite", true, true, nil, false, ""},
		{"gemini-3.1-flash-image", true, true, nil, false, ""},
		{"unversioned", true, true, nil, false, ""},
	} {
		req := vertexToolRequest()
		req.Stream, req.ToolChoice = tc.stream, tc.choice
		if !tc.tools {
			req.Tools = nil
		}
		payload, err := vertexGeminiPayload(t.Context(), req, nil, tc.model)
		if err != nil {
			t.Fatal(err)
		}
		config, _ := payload["toolConfig"].(map[string]any)
		calling, _ := config["functionCallingConfig"].(map[string]any)
		flag, present := calling["streamFunctionCallArguments"]
		if present != tc.want || (present && flag != true) || stringValue(calling["mode"]) != tc.mode {
			t.Fatalf("%+v: got %v", tc, config)
		}
	}
}

func TestAIStudioDoesNotRequestVertexToolStream(t *testing.T) {
	c := aiStudioGeminiClient{apiKey: "fixture", baseURL: googleAIStudioNativeBaseURL,
		httpc: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var payload map[string]any
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				return nil, err
			}
			if _, ok := payload["tools"]; !ok || vertexStreamsToolArgs(payload) {
				t.Fatalf("unexpected AI Studio tool config: %v", payload["toolConfig"])
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(geminiToolFinish))}, nil
		})},
	}
	if err := c.InvokeStreaming(t.Context(), vertexToolRequest(), nil, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func geminiCallEvent(call string) string {
	return "data: " + `{"candidates":[{"content":{"parts":[{` + call + `}]}}]}` + "\n\n"
}

const geminiToolFinish = "data: " + `{"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":4,"thoughtsTokenCount":2}}` + "\n\n"

type vertexSignalingWriter struct {
	bytes.Buffer
	first chan struct{}
}

func (w *vertexSignalingWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if w.first != nil && bytes.Contains(w.Bytes(), []byte("early-fragment")) {
		close(w.first)
		w.first = nil
	}
	return n, err
}

// Hold back the rest of the Vertex response until the public Chat Completions
// adapter actually writes the first argument fragment. No wall-clock latency
// comparison or sorting of already-buffered events can satisfy this test.
func TestVertexArgumentsReachChatClientBeforeCallFinishes(t *testing.T) {
	up, send := io.Pipe()
	internal, translated := io.Pipe()
	t.Cleanup(func() { up.Close(); send.Close(); internal.Close(); translated.Close() })
	client := &vertexGeminiClient{auth: &gcpClient{
		projectID: "test", region: "global", token: "fixture", tokenExp: time.Now().Add(time.Hour),
		httpc: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var payload map[string]any
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				return nil, err
			}
			if !strings.HasSuffix(req.URL.Path, "/gemini-4-argon:streamGenerateContent") || !vertexStreamsToolArgs(payload) {
				t.Errorf("unexpected Vertex streaming request")
			}
			return &http.Response{StatusCode: 200, Body: up, Header: make(http.Header)}, nil
		})},
	}}
	go func() {
		err := client.InvokeStreaming(t.Context(), vertexToolRequest(), nil, translated, InvokeOptions{Provider: "google-vertex", UpstreamModel: "gemini-4-argon"})
		translated.CloseWithError(err)
	}()
	first := make(chan struct{})
	out := &vertexSignalingWriter{first: first}
	type result struct {
		r   adapter.StreamResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := adapter.TransformStreamCapture(internal, out, "req", "gemini-4-argon")
		done <- result{r, err}
	}()
	write := func(wire string) {
		t.Helper()
		if _, err := io.WriteString(send, wire); err != nil {
			t.Fatal(err)
		}
	}
	write(geminiCallEvent(`"thoughtSignature":"c2ln","functionCall":{"name":"lookup","willContinue":true}`) +
		geminiCallEvent(`"functionCall":{"partialArgs":[{"jsonPath":"$.items[0].text","stringValue":"early-fragment","willContinue":true}],"willContinue":true}`))
	select {
	case <-first:
	case <-time.After(3 * time.Second):
		t.Fatal("no Chat Completions argument delta before Vertex completion")
	}
	write(geminiCallEvent(`"functionCall":{"partialArgs":[{"jsonPath":"$.items[0].text","stringValue":"\n\"\\","willContinue":true},{"jsonPath":"$.items[0].text"},{"jsonPath":"$.items[1]","boolValue":false},{"jsonPath":"$['a.b']","nullValue":null},{"jsonPath":"$.n","numberValue":9007199254740993}],"willContinue":true}`) +
		geminiCallEvent(`"functionCall":{}`) +
		geminiCallEvent(`"functionCall":{"name":"lookup","willContinue":true}`) +
		geminiCallEvent(`"functionCall":{"partialArgs":[{"jsonPath":"$.empty","stringValue":""}]}`) + geminiToolFinish)
	send.Close()
	res := <-done
	if res.err != nil {
		t.Fatal(res.err)
	}
	r := res.r
	if len(r.ToolCalls) != 2 || r.ToolCalls[0].ID != "call_1"+geminiSignatureDelimiter+"c2ln" || r.ToolCalls[1].ID != "call_2" || r.FinishReason != "tool_calls" {
		t.Fatalf("calls %+v, finish %q", r.ToolCalls, r.FinishReason)
	}
	want := `{"items":[{"text":"early-fragment\n\"\\"},false],"a.b":null,"n":9007199254740993}`
	if r.ToolCalls[0].Arguments != want || r.ToolCalls[1].Arguments != `{"empty":""}` {
		t.Fatalf("arguments: %+v", r.ToolCalls)
	}
	if r.Usage == nil || r.Usage.InputTokens != 10 || r.Usage.OutputTokens != 6 {
		t.Fatalf("usage: %+v", r.Usage)
	}
}

func TestGeminiPartialArgPaths(t *testing.T) {
	v := true
	for _, tc := range []struct {
		paths []string
		want  string
	}{
		{[]string{`$["x.y"][0][0]`, `$["x.y"][0][1]`, `$["x.y"][1][0]`, `$['quo\'te"\\']`}, `{"x.y":[[true,true],[true]],"quo'te\"\\":true}`},
		{[]string{"$.x", "$.x"}, ""},
		{[]string{"$.x[1]"}, ""},
		{[]string{"$.x[0]", "$.x.key"}, ""},
		{[]string{"$.x.a", "$.y", "$.x.b"}, ""},
		{[]string{"$.*"}, ""},
		{[]string{"$..x"}, ""},
		{[]string{"$"}, ""},
		{[]string{"$[0]"}, ""},
		{[]string{"$['unterminated]"}, ""},
		{[]string{"$" + strings.Repeat(".a", 129)}, ""},
	} {
		s := geminiArgumentStream{frames: []geminiArgFrame{{}}}
		var b strings.Builder
		b.WriteByte('{')
		var err error
		for _, path := range tc.paths {
			if err = s.appendArg(&b, geminiPartialArg{JSONPath: path, BoolValue: &v}); err != nil {
				break
			}
		}
		if tc.want == "" {
			if err == nil {
				t.Errorf("accepted invalid path sequence %q", tc.paths)
			}
			continue
		}
		s.closeTo(&b, 0)
		if err != nil || b.String() != tc.want {
			t.Errorf("%q: got %s (%v), want %s", tc.paths, b.String(), err, tc.want)
		}
	}
}

func TestVertexIncompleteArgsCannotFinish(t *testing.T) {
	head := geminiCallEvent(`"functionCall":{"name":"lookup","willContinue":true,"partialArgs":[{"jsonPath":"$.k","stringValue":"a","willContinue":true}]}`)
	for _, tail := range []string{"", geminiToolFinish,
		geminiCallEvent(`"functionCall":{}`),
		geminiCallEvent(`"functionCall":{"partialArgs":[{"jsonPath":"$.other","stringValue":"b"}]}`),
		geminiCallEvent(`"functionCall":{"args":{"k":"ab"}}`),
		"data: not-json\n\n",
	} {
		var out bytes.Buffer
		err := translateGeminiStreamToAnthropicMode(strings.NewReader(head+tail), &out, true)
		if err == nil || strings.Contains(out.String(), "message_stop") || strings.Contains(out.String(), "content_block_stop") {
			t.Fatalf("truncated or invalid call was completed: %v %s", err, out.String())
		}
	}
}
