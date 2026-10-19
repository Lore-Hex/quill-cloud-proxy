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

type regoloDecisionTransport func(*http.Request) (*http.Response, error)

func (f regoloDecisionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRegoloDecisionBYOKNeverUsesOperatorKey(t *testing.T) {
	for _, operatorKey := range []string{"operator-key", ""} {
		for _, customerKey := range []string{"customer-key", ""} {
			t.Run(operatorKey+"/"+customerKey, func(t *testing.T) {
				calls := 0
				client := &openAICompatibleClient{provider: "regolo", baseURL: directBaseURL("regolo"), apiKey: operatorKey,
					httpc: &http.Client{Transport: regoloDecisionTransport(func(r *http.Request) (*http.Response, error) {
						calls++
						if r.URL.String() != "https://api.regolo.ai/v1/systemone" || r.Header.Get("Authorization") != "Bearer customer-key" {
							t.Error("BYOK used the wrong provider endpoint or credential")
						}
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"model":"clef-flash","usage":{"input_tokens":62,"output_tokens":0},"answers":{}}`))}, nil
					})}}
				_, err := client.InvokeDecide(context.Background(), &DecideRequest{Model: "cloudflare/clef-flash"}, InvokeOptions{
					Provider: "regolo", UpstreamModel: "clef-flash", UsageType: "BYOK", ProviderAPIKey: customerKey,
				})
				if customerKey == "" {
					if DecideErrorClass(err) != DecideErrConfig || calls != 0 {
						t.Fatalf("missing BYOK must fail before inference: class=%s calls=%d", DecideErrorClass(err), calls)
					}
				} else if err != nil || calls != 1 {
					t.Fatalf("BYOK failed: class=%s calls=%d", DecideErrorClass(err), calls)
				}
				if client.apiKey != operatorKey {
					t.Error("BYOK mutated the shared prepaid client")
				}
			})
		}
	}
}

func TestRegoloDecisionWireAndUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/systemone" || r.Header.Get("Authorization") != "Bearer test" || r.Header.Get("S1-Region") != "" {
			t.Error("incorrect decision path or credentials")
		}
		var wire DecideRequest
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		if wire.Model != "clef-flash" || wire.Questions["red"].Type != "noul" || len(wire.Questions) != 3 {
			t.Error("lost model or typed questions")
		}
		_, _ = w.Write([]byte(`{"model":"clef-flash","answers":{"red":{"type":"noul","noul":0.99},"color":{"type":"choice","choice":"red","probabilities":{"red":0.99,"blue":0.01}},"score":{"type":"score","score":1.9,"probabilities":{"0":0.02,"1":0.06,"2":0.92}}},"usage":{"input_tokens":140,"output_tokens":0}}`))
	}))
	defer server.Close()
	client := &openAICompatibleClient{provider: "regolo", baseURL: server.URL + "/v1", apiKey: "test", httpc: server.Client()}
	req := &DecideRequest{Model: "cloudflare/clef-flash", State: json.RawMessage(`"Mia owns a red bicycle."`), Questions: map[string]decide.Question{
		"red":   {Type: decide.TypeBoolean, Instructions: "Is it red?"},
		"color": {Type: decide.TypeChoice, Instructions: "What color?", Criteria: json.RawMessage(`{"red":null,"blue":null}`)},
		"score": {Type: decide.TypeScore, Instructions: "How red?", Criteria: json.RawMessage(`["Not red","Unclear","Clearly red"]`)},
	}}
	response, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: "regolo", UpstreamModel: "clef-flash"})
	if err != nil {
		t.Fatal(err)
	}
	specs, err := decide.Parse(req.Questions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decide.Verify(specs, response.Answers); err != nil {
		t.Fatal(err)
	}
	if response.InputTokens != 140 || response.OutputTokens != 0 || req.Questions["red"].Type != decide.TypeBoolean {
		t.Fatalf("bad usage or request mutation: %+v", response)
	}
}

func TestRegoloDecisionRejectsWrongModelAndUsage(t *testing.T) {
	for _, body := range []string{
		`{"model":"another-model","usage":{"input_tokens":62,"output_tokens":0}}`,
		`{"model":"clef-flash"}`,
		`{"model":"clef-flash","usage":{"input_tokens":62}}`,
		`{"model":"clef-flash","usage":{"input_tokens":0,"output_tokens":0}}`,
		`{"model":"clef-flash","usage":{"input_tokens":-1,"output_tokens":0}}`,
		`{"model":"clef-flash","usage":{"input_tokens":62,"output_tokens":1}}`,
		`{"model":"clef-flash","usage":{"input_tokens":62,"output_tokens":false}}`,
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			client := &openAICompatibleClient{provider: "regolo", baseURL: server.URL, apiKey: "test", httpc: server.Client()}
			_, err := client.InvokeDecide(context.Background(), &DecideRequest{Model: "clef-flash"})
			if DecideErrorClass(err) != DecideErrDecode {
				t.Fatalf("ambiguous response accepted: %v", err)
			}
		})
	}
}
