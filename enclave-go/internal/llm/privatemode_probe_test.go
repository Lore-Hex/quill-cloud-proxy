package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
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
		var results []PrivatemodeProbeResult
		ProbePrivatemode(t.Context(), client, "synthetic-key", func(r PrivatemodeProbeResult) { results = append(results, r) })
		if calls != 3 || len(results) != 3 {
			t.Fatal("probe retried or exceeded model budget")
		}
		for _, r := range results {
			if r.Success != (status == 200) || (status != 200 && r.HTTPStatus != status) {
				t.Fatalf("unexpected probe result: %+v", r)
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
	ProbePrivatemode(ctx, nil, "", func(PrivatemodeProbeResult) { t.Fatal("canceled probe executed") })
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
