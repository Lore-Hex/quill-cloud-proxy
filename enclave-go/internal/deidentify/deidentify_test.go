package deidentify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

const testToken = "[TRABCDEFGHIJKLMNOP_EMAIL_1]"

type fakeRunner struct {
	fail  bool
	calls int
}

func (r *fakeRunner) Protect(_ context.Context, texts []string) (Result, error) {
	r.calls++
	if r.fail {
		return Result{}, ErrUnavailable
	}
	out := Result{Texts: make([]string, len(texts)), Replacements: map[string]string{testToken: "alice@example.com"}}
	for i, s := range texts {
		out.Texts[i] = strings.ReplaceAll(s, "alice@example.com", testToken)
	}
	return out, nil
}

func TestPrepareSurfaces(t *testing.T) {
	for _, tc := range []struct{ route, raw string }{
		{"chat.completions", `{"model":"anthropic/claude-opus-5.5","deidentify":true,"messages":[{"role":"system","content":"alice@example.com"},{"role":"user","content":[{"type":"text","text":"alice@example.com"}]},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"send","arguments":"{\"email\":\"alice@example.com\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"alice@example.com"}],"tools":[{"type":"function","function":{"name":"send","description":"alice@example.com","parameters":{"type":"object","properties":{"email":{"type":"string","description":"alice@example.com"}}}}}]}`},
		{"responses", `{"model":"openai/gpt-5","deidentify":true,"instructions":"alice@example.com","input":[{"role":"user","content":[{"type":"input_text","text":"alice@example.com"}]},{"type":"function_call","name":"send","call_id":"a","arguments":"{\"email\":\"alice@example.com\"}"},{"type":"function_call_output","call_id":"a","output":"alice@example.com"}]}`},
		{"messages", `{"model":"claude-opus-5.5","deidentify":true,"system":[{"type":"text","text":"alice@example.com","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"a","name":"send","input":{"email":"alice@example.com"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"a","content":"alice@example.com"}]}],"max_tokens":256}`},
	} {
		t.Run(tc.route, func(t *testing.T) {
			safe, s, err := Prepare(context.Background(), []byte(tc.raw), tc.route, &fakeRunner{})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(safe), "alice@example.com") || strings.Contains(string(safe), "deidentify") {
				t.Fatalf("unprotected field: %s", safe)
			}
			if !json.Valid(safe) || s.reveal(testToken, false) != "alice@example.com" {
				t.Fatal("invalid response/map")
			}
		})
	}
}

func TestUnsupportedNeverCallsWorker(t *testing.T) {
	for _, extra := range []string{
		`"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/image.png"}}]}]`,
		`"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"secret","signature":"opaque"}]}]`,
		`"messages":[],"plugins":[{"id":"web"}]`,
		`"messages":[],"tools":[{"type":"web_search"}]`,
		`"messages":[],"prediction":{"content":"private"}`,
		`"messages":[],"prompt_cache_key":"private"`,
		`"messages":[],"unknown":"private"`,
	} {
		r := &fakeRunner{}
		_, _, err := Prepare(context.Background(), []byte(`{"deidentify":true,"model":"test",`+extra+`}`), "chat.completions", r)
		if !errors.Is(err, ErrUnsupported) || r.calls != 0 {
			t.Fatalf("unsupported: %s %v %d", extra, err, r.calls)
		}
	}
}

func TestFailureAndImmutableIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		fail bool
		want error
	}{
		{`{"deidentify":true,"messages":[]}`, true, ErrUnavailable},
		{`{"deidentify":true,"messages":[{"role":"user","name":"alice@example.com","content":"hello"}]}`, false, ErrUnsupported},
	} {
		_, _, err := Prepare(context.Background(), []byte(tc.raw), "chat.completions", &fakeRunner{fail: tc.fail})
		if !errors.Is(err, tc.want) {
			t.Fatal(err)
		}
	}
}

func TestToolNumbersRemainExact(t *testing.T) {
	raw := []byte(`{"deidentify":true,"messages":[{"role":"assistant","tool_calls":[{"id":"a","type":"function","function":{"name":"calculate","arguments":"{\"value\":9007199254740993}"}}]}]}`)
	safe, _, err := Prepare(context.Background(), raw, "chat.completions", &fakeRunner{})
	if err != nil || !strings.Contains(string(safe), "9007199254740993") {
		t.Fatalf("number changed: %s %v", safe, err)
	}
}

func TestStreamingEveryByteSplitAndJSONEscaping(t *testing.T) {
	secret := "Alice \"A\"\nSmith"
	s := &Session{replacements: map[string]string{testToken: secret}}
	for _, field := range []string{"text", "partial_json"} {
		kind := map[string]string{"text": "text_delta", "partial_json": "input_json_delta"}[field]
		for split := 0; split <= len(testToken); split++ {
			var out bytes.Buffer
			w := s.Writer(&out)
			for _, part := range []string{testToken[:split], testToken[split:]} {
				b, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": kind, field: part}})
				for _, c := range []byte("data: " + string(b) + "\n\n") {
					if _, err := w.Write([]byte{c}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := io.WriteString(w, "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n"); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			var result strings.Builder
			for _, line := range strings.Split(out.String(), "\n") {
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				var event map[string]any
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
					t.Fatal(err)
				}
				if d, ok := event["delta"].(map[string]any); ok {
					result.WriteString(d[field].(string))
				}
			}
			want := secret
			if field == "partial_json" {
				b, _ := json.Marshal(secret)
				want = string(b[1 : len(b)-1])
			}
			if result.String() != want {
				t.Fatalf("%s split %d got %q", field, split, result.String())
			}
		}
	}
}

func TestStreamFailureTruncationUsageAndUnknownTokens(t *testing.T) {
	s := &Session{replacements: map[string]string{testToken: "secret"}}
	if s.reveal("[EMAIL_1]", false) != "[EMAIL_1]" {
		t.Fatal("literal collision")
	}
	var out bytes.Buffer
	w := s.Writer(&out)
	if _, err := io.WriteString(w, "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n\n"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"output_tokens":9`) {
		t.Fatal("usage changed")
	}
	_, _ = io.WriteString(w, "data: {")
	if !errors.Is(w.Close(), io.ErrUnexpectedEOF) {
		t.Fatal("accepted truncation")
	}
	w = s.Writer(failingWriter{})
	if _, err := io.WriteString(w, "data: {\"type\":\"message_stop\"}\n\n"); err == nil {
		t.Fatal("lost write failure")
	}
}

type failingWriter struct{}

func TestWorkerBoundsCancellationAndMissingRuntime(t *testing.T) {
	w := NewWorker("/does-not-exist", "/missing.mjs")
	if _, err := w.Protect(context.Background(), []string{"private"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.Protect(ctx, []string{"private"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	w.slots <- struct{}{}
	w.slots <- struct{}{}
	if _, err := w.Protect(context.Background(), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	var b boundedBuffer
	if _, err := b.Write(make([]byte, 4<<20)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte{0}); err == nil {
		t.Fatal("unbounded worker output")
	}
}

func TestStreamInitialTextPrefixAndExpansionBound(t *testing.T) {
	s := &Session{replacements: map[string]string{testToken: "Alice"}}
	var output bytes.Buffer
	w := s.Writer(&output)
	start, _ := json.Marshal(map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": testToken[:10]}})
	delta, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": testToken[10:]}})
	for _, data := range [][]byte{start, delta, []byte(`{"type":"content_block_stop","index":0}`)} {
		if _, err := io.WriteString(w, "data: "+string(data)+"\n\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil || !strings.Contains(output.String(), `"text":"Alice"`) {
		t.Fatalf("%s %v", output.String(), err)
	}
	s = &Session{replacements: map[string]string{testToken: strings.Repeat("A", 256<<10)}}
	w = s.Writer(&bytes.Buffer{})
	b, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": testToken}})
	if _, err := io.WriteString(w, "data: "+string(b)+"\n\n"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unbounded expansion", err)
	}
}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestStreamPreservesExactToolNumbers(t *testing.T) {
	s := &Session{replacements: map[string]string{testToken: "Alice"}}
	var out bytes.Buffer
	w := s.Writer(&out)
	data := `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","name":"calculate","input":{"value":9007199254740993,"person":"` + testToken + `"}}}`
	if _, err := io.WriteString(w, "data: "+data+"\n\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil || !strings.Contains(out.String(), `"value":9007199254740993`) || !strings.Contains(out.String(), `"person":"Alice"`) {
		t.Fatalf("tool input changed: %s %v", out.String(), err)
	}
	for _, index := range []string{`null`, `"0"`, `0.5`, `-1`, `1e999`} {
		w := s.Writer(io.Discard)
		if _, err := io.WriteString(w, `data: {"type":"content_block_stop","index":`+index+"}\n\n"); err == nil {
			t.Fatal("accepted invalid index", index)
		}
	}
}

func TestStructuredTextRestorationEscapesJSONValues(t *testing.T) {
	for _, raw := range []string{
		`{"deidentify":true,"messages":[],"response_format":{"type":"json_object"}}`,
		`{"deidentify":true,"input":"hi","text":{"format":{"type":"json_schema","name":"reply","schema":{"type":"object"}}}}`,
	} {
		_, session, err := Prepare(context.Background(), []byte(raw), "chat.completions", &fakeRunner{})
		if err != nil || !session.jsonText {
			t.Fatalf("structured format not recognized: %s %v", raw, err)
		}
		secret := "Alice \"A\"\nSmith"
		session.replacements[testToken] = secret
		var out bytes.Buffer
		w := session.Writer(&out)
		for _, text := range []string{`{"person":"` + testToken[:12], testToken[12:] + `"}`} {
			data, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": text}})
			if _, err := io.WriteString(w, "data: "+string(data)+"\n\n"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := io.WriteString(w, "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n"); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		var text strings.Builder
		for _, line := range strings.Split(out.String(), "\n") {
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var event map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
				t.Fatal(err)
			}
			if delta, ok := event["delta"].(map[string]any); ok {
				text.WriteString(delta["text"].(string))
			}
		}
		var result map[string]string
		if json.Unmarshal([]byte(text.String()), &result) != nil || result["person"] != secret {
			t.Fatalf("restored JSON invalid: %s", text.String())
		}
	}
}

func TestSignedReasoningRemainsUnmodified(t *testing.T) {
	s := &Session{replacements: map[string]string{testToken: "Alice"}}
	var out bytes.Buffer
	w := s.Writer(&out)
	for _, data := range []string{
		`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"` + testToken + `","signature":"signed-prefix"}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"` + testToken + `"}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"signed-suffix"}}`,
		`{"type":"content_block_stop","index":0}`,
	} {
		if _, err := io.WriteString(w, "data: "+data+"\n\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil || strings.Contains(out.String(), "Alice") || strings.Count(out.String(), testToken) != 2 || !strings.Contains(out.String(), "signed-prefix") || !strings.Contains(out.String(), "signed-suffix") {
		t.Fatalf("signed content was changed: %s %v", out.String(), err)
	}
}
