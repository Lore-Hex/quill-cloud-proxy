package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestPrivatemodeBootProbeIsBoundedAndMetadataOnly(t *testing.T) {
	for _, status := range []int{200, 401, 429, 503} {
		calls := 0
		client := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.String() != "https://privatemode.internal:18489/v1/chat/completions" {
				t.Fatal("probe escaped encrypted proxy")
			}
			var request map[string]any
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request["max_tokens"] != float64(1024) || request["reasoning_effort"] != "low" {
				t.Fatal("probe lost cost bound")
			}
			body := "sensitive-error-body"
			if status == 200 {
				body = "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\",\"reasoning_content\":\"sensitive-thinking\"},\"finish_reason\":\"stop\"}]}\n\n" +
					"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":21,\"completion_tokens\":4}}\n\ndata: [DONE]\n\n"
			}
			return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		ConfigurePrivatemode(client)
		t.Cleanup(func() { ConfigurePrivatemode(nil) })
		var results []PrivatemodeProbeResult
		ProbePrivatemode(t.Context(), "synthetic-key", func(r PrivatemodeProbeResult) { results = append(results, r) })
		if calls != 3 || len(results) != 3 {
			t.Fatal("probe retried or exceeded model budget")
		}
		for _, r := range results {
			if r.Success != (status == 200) || (status != 200 && r.HTTPStatus != status) {
				t.Fatalf("unexpected probe result: %+v", r)
			}
			if (r.Success && r.Reason != "ok") || (!r.Success && r.Reason != "http") {
				t.Fatalf("unexpected reason: %+v", r)
			}
		}
		encoded, _ := json.Marshal(results)
		for _, forbidden := range []string{"PONG", "sensitive", "synthetic-key"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatal("probe leaked content")
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ProbePrivatemode(ctx, "", func(PrivatemodeProbeResult) { t.Fatal("canceled probe executed") })
}

func TestPrivatemodeProbeBoundsMemory(t *testing.T) {
	b := &privatemodeProbeBuffer{}
	if _, err := b.Write(make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte{0}); err == nil {
		t.Fatal("unbounded probe output")
	}
}

func TestPrivatemodeProbeFailureCategories(t *testing.T) {
	t.Cleanup(func() { ConfigurePrivatemode(nil) })
	ConfigurePrivatemode(nil)
	if got := probePrivatemodeModel(t.Context(), "key", "glm-5.3"); got.Reason != "configuration" || got.Success {
		t.Fatalf("missing configured proxy succeeded: %+v", got)
	}
	for _, tc := range []struct {
		name, text, want string
		transport        bool
		truncated        bool
		canceled         bool
		zeroOutput       bool
	}{
		{name: "punctuation", text: "\"pong.\"", want: "ok"},
		{name: "markdown", text: "**PONG**", want: "ok"},
		{name: "wrong text", text: "unrelated", want: "text"},
		{name: "transport", want: "transport", transport: true},
		{name: "truncated", want: "stream", truncated: true},
		{name: "canceled", want: "timeout_or_cancel", canceled: true},
		{name: "usage", text: "PONG", want: "usage", zeroOutput: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ConfigurePrivatemode(&http.Client{Transport: byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
				if tc.transport {
					return nil, &url.Error{Op: "POST", URL: "redacted", Err: io.EOF}
				}
				content, _ := json.Marshal(tc.text)
				body := "data: {\"choices\":[{\"delta\":{\"content\":" + string(content) + "},\"finish_reason\":\"stop\"}]}\n\n"
				if !tc.truncated {
					tokens := "4"
					if tc.zeroOutput {
						tokens = "0"
					}
					body += "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":21,\"completion_tokens\":" + tokens + "}}\n\ndata: [DONE]\n\n"
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			got := probePrivatemodeModel(ctx, "key", "glm-5.3")
			if got.Reason != tc.want || got.Success != (tc.want == "ok") {
				t.Fatalf("got %+v, want %s", got, tc.want)
			}
		})
	}
}
