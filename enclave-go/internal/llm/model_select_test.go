package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

type selectionTransport func(*http.Request) (*http.Response, error)

func (f selectionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func selectorForTest(t *testing.T, fn selectionTransport) *TelluvianSelector {
	t.Helper()
	client, err := NewTelluvianSelector("test-secret-do-not-log", &http.Client{Transport: fn})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func selectionResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestTelluvianSelectLiveContract(t *testing.T) {
	const prompt = `{"messages":[{"role":"system","content":"Be concise"},{"role":"user","content":"Synthetic task"}],"tools":[]}`
	client := selectorForTest(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != telluvianSelectorURL || req.Method != "POST" {
			t.Fatalf("wrong target: %s %s", req.Method, req.URL)
		}
		if req.Header.Get("Authorization") != "Bearer test-secret-do-not-log" {
			t.Fatal("missing auth")
		}
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 2 || body["messages"] != prompt || body["xPerf"] != .9 {
			t.Fatalf("wrong request: %#v", body)
		}
		deadline, ok := req.Context().Deadline()
		if !ok || time.Until(deadline) > selectionTimeout {
			t.Fatal("unbounded call")
		}
		return selectionResponse(200, `{"model":"gemini-3.8-flash","reasoning":{"effort":"high"},"sessionId":"synthetic"}`), nil
	})
	result, err := client.Select(context.Background(), prompt, SelectionControls{XPerf: .9}, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Model != "gemini-3.8-flash" || result.Reasoning.Effort != "high" || result.SessionID != "synthetic" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestTelluvianSelectSessionContractAndNoSharedState(t *testing.T) {
	const first = "3f2b7c58-9d41-4e0a-9a7c-6f0b1c2d3e4f"
	const second = "4f2b7c58-9d41-8e0a-aa7c-6f0b1c2d3e4f"
	wanted := ""
	client := selectorForTest(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != telluvianSelectorURL {
			t.Fatal("session request left direct Model Select")
		}
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["messages"] != "Synthetic turn" || body["xPerf"] != .9 {
			t.Fatal("session changed selection context or quality")
		}
		if wanted == "" {
			if _, exists := body["sessionId"]; exists || len(body) != 2 {
				t.Fatal("one-shot request reused a session")
			}
		} else if body["sessionId"] != wanted || len(body) != 3 {
			t.Fatalf("incorrect session body: %#v", body)
		}
		return selectionResponse(200, `{"model":"gemini-3.8-flash","sessionId":"`+wanted+`"}`), nil
	})
	for _, session := range []string{first, second, "", first} {
		wanted = session
		result, err := client.Select(context.Background(), "Synthetic turn", SelectionControls{XPerf: .9}, session)
		if err != nil || result.SessionID != session {
			t.Fatalf("session round trip failed: result=%#v err=%v", result, err)
		}
	}
}

func TestTelluvianSelectRejectsInvalidSessionBeforeNetwork(t *testing.T) {
	client := selectorForTest(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid session reached upstream")
		return nil, nil
	})
	for _, session := range []string{"private-id", " ", "3f2b7c58-9d41-4e0a-9a7c-6f0b1c2d3e4g", strings.Repeat("a", 256)} {
		_, err := client.Select(context.Background(), "Synthetic prompt", SelectionControls{XPerf: .9}, session)
		var failure *SelectionError
		if !errors.As(err, &failure) || failure.Class != "invalid_request" || err.Error() != "telluvian selection: invalid_request" {
			t.Fatalf("unsafe validation error: %v", err)
		}
	}
}

func TestTelluvianSelectRejectsInvalidResponse(t *testing.T) {
	for name, body := range map[string]string{
		"empty": `{}`, "null": `null`, "array": `[]`, "truncated": `{"model":`,
		"duplicate":        `{"model":"gpt-5.5","model":"gemini-3.8-flash"}`,
		"nested_duplicate": `{"model":"gpt-5.5","reasoning":{"effort":"low","effort":"high"}}`,
		"url":              `{"model":"https://attacker.example/model"}`,
		"recursive":        `{"model":"trustedrouter/polyphemus-1.0"}`,
		"traversal":        `{"model":"../gpt-5.5"}`,
		"whitespace":       `{"model":" gpt-5.5"}`,
		"effort":           `{"model":"gpt-5.5","reasoning":{"effort":"unexpected"}}`,
		"type":             `{"model":42}`,
		"oversized":        strings.Repeat("x", maxSelectionResponseBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			client := selectorForTest(t, func(*http.Request) (*http.Response, error) { return selectionResponse(200, body), nil })
			result, err := client.Select(context.Background(), "Synthetic prompt", SelectionControls{XPerf: .9}, "")
			if result != nil || err == nil {
				t.Fatalf("accepted %s", name)
			}
			if strings.Contains(err.Error(), body) || strings.Contains(err.Error(), "test-secret") {
				t.Fatal("error leaked upstream data")
			}
		})
	}
}

func TestTelluvianSelectDoesNotRetryOrFollowRedirects(t *testing.T) {
	for _, status := range []int{301, 307, 400, 401, 402, 429, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			client := selectorForTest(t, func(*http.Request) (*http.Response, error) {
				calls++
				r := selectionResponse(status, "private prompt test-secret-do-not-log")
				r.Header.Set("Location", "https://attacker.example/")
				return r, nil
			})
			_, err := client.Select(context.Background(), "private prompt", SelectionControls{XPerf: .9}, "")
			var failure *SelectionError
			if !errors.As(err, &failure) || failure.Status != status || calls != 1 {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
			if strings.Contains(err.Error(), "private prompt") || strings.Contains(err.Error(), "test-secret") {
				t.Fatal("content leaked")
			}
		})
	}
}

func TestTelluvianSelectRequestValidationBeforeNetwork(t *testing.T) {
	for _, tc := range []struct {
		prompt string
		perf   float64
	}{
		{"", .9}, {" ", .9}, {strings.Repeat("a", maxSelectionInputBytes+1), .9}, {"ok", -1}, {"ok", 1.01}, {"ok", math.NaN()}, {"ok", math.Inf(1)},
	} {
		client := selectorForTest(t, func(*http.Request) (*http.Response, error) {
			t.Fatal("invalid request reached upstream")
			return nil, nil
		})
		if _, err := client.Select(context.Background(), tc.prompt, SelectionControls{XPerf: tc.perf}, ""); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
}

func TestTelluvianSelectCancellationAndErrorRedaction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := selectorForTest(t, func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })
	_, err := client.Select(ctx, "Synthetic prompt", SelectionControls{XPerf: .9}, "")
	var failure *SelectionError
	if !errors.As(err, &failure) || failure.Class != "canceled" {
		t.Fatalf("got %v", err)
	}
	client = selectorForTest(t, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("private prompt test-secret-do-not-log")
	})
	_, err = client.Select(context.Background(), "Synthetic prompt", SelectionControls{XPerf: .9}, "")
	if !errors.As(err, &failure) || failure.Class != "transport" || strings.Contains(err.Error(), "test-secret") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestTelluvianSelectRequiresExplicitTransportAndKey(t *testing.T) {
	for _, tc := range []struct {
		key    string
		client *http.Client
	}{{"", &http.Client{}}, {"secret", nil}} {
		if _, err := NewTelluvianSelector(tc.key, tc.client); err == nil {
			t.Fatal("missing configuration accepted")
		}
	}
}

func TestTelluvianSelectSendsCallerControls(t *testing.T) {
	var body map[string]any
	client := selectorForTest(t, func(req *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return selectionResponse(200, `{"model":"gpt-6-astra","reasoning":{"effort":"high"}}`), nil
	})
	controls := SelectionControls{XPerf: "openai/gpt-6-astra", ModelZoo: "openai/*, anthropic/claude-opus*"}
	if _, err := client.Select(context.Background(), "Synthetic prompt", controls, ""); err != nil {
		t.Fatal(err)
	}
	if len(body) != 3 || body["xPerf"] != "openai/gpt-6-astra" || body["modelZoo"] != "openai/*, anthropic/claude-opus*" {
		t.Fatalf("controls not forwarded exactly: %#v", body)
	}
}

func TestSelectionControlsValidation(t *testing.T) {
	valid := []SelectionControls{
		{XPerf: MinSelectionXPerf}, {XPerf: 1.0}, {XPerf: "claude-sonnet-5"}, {XPerf: "openai/gpt-6-astra"},
		{XPerf: .9, ModelZoo: "openai/*,anthropic/claude-opus*"}, {XPerf: .9, ModelZoo: "*"},
	}
	for _, c := range valid {
		if field := c.Validate(); field != "" {
			t.Fatalf("%#v rejected on %s", c, field)
		}
	}
	for _, tc := range []struct {
		controls SelectionControls
		field    string
	}{
		{SelectionControls{}, "x_perf"},
		{SelectionControls{XPerf: 0.09}, "x_perf"},
		{SelectionControls{XPerf: 1.01}, "x_perf"},
		{SelectionControls{XPerf: math.NaN()}, "x_perf"},
		{SelectionControls{XPerf: ""}, "x_perf"},
		{SelectionControls{XPerf: "openai/gpt 6"}, "x_perf"},
		{SelectionControls{XPerf: "a/b/c"}, "x_perf"},
		{SelectionControls{XPerf: strings.Repeat("a", 129)}, "x_perf"},
		{SelectionControls{XPerf: true}, "x_perf"},
		{SelectionControls{XPerf: .9, ModelZoo: "openai/*,"}, "model_zoo"},
		{SelectionControls{XPerf: .9, ModelZoo: "openai/$x"}, "model_zoo"},
		{SelectionControls{XPerf: .9, ModelZoo: strings.Repeat("a,", 64) + "a"}, "model_zoo"},
		{SelectionControls{XPerf: .9, ModelZoo: strings.Repeat("a", 2049)}, "model_zoo"},
	} {
		if field := tc.controls.Validate(); field != tc.field {
			t.Fatalf("%#v: got %q, want %q", tc.controls, field, tc.field)
		}
	}
}
