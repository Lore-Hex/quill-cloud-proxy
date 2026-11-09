package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

const basetenMammoth = "decision-models/baseten-mammoth-27b-latest"

// Body shape from https://docs.baseten.co/inference/model-apis/decision-models.
const basetenDecisionBody = `{"model":"decision-models/baseten-mammoth-27b-latest","answers":{"red":{"type":"noul","noul":0.99},"color":{"type":"choice","choice":"red","confidence":0.99,"probabilities":{"red":0.995,"blue":0.005}},"score":{"type":"score","score":1.9,"confidence":0.8,"legend":{"0":"Not red","1":"Unclear","2":"Clearly red"},"probabilities":{"0":0.02,"1":0.06,"2":0.92}}},"usage":{"input_tokens":231,"output_tokens":3}}`

func basetenDecideRequest() *DecideRequest {
	return &DecideRequest{Model: basetenMammoth, State: json.RawMessage(`"Mia owns a red bicycle."`), Questions: map[string]decide.Question{
		"red":   {Type: decide.TypeBoolean, Instructions: "Is it red?"},
		"color": {Type: decide.TypeChoice, Instructions: "What color?", Criteria: json.RawMessage(`{"red":null,"blue":null}`)},
		"score": {Type: decide.TypeScore, Instructions: "How red?", Criteria: json.RawMessage(`["Not red","Unclear","Clearly red"]`)},
	}}
}

func TestBasetenDecisionModelsAreHosted(t *testing.T) {
	for _, model := range []string{
		"decision-models/baseten-elephant-9b-latest",
		basetenMammoth,
		"decision-models/baseten-joey-2b-latest",
	} {
		if !decide.IsHostedModel(model) || !isBasetenSystemOneModel(model) {
			t.Errorf("%s must take the hosted System One path", model)
		}
	}
	for _, model := range []string{"decision-models/baseten-future", "moonshotai/Kimi-K3", "typesafe-ai/jev"} {
		if isBasetenSystemOneModel(model) {
			t.Errorf("%s is not a reviewed Baseten System One model", model)
		}
	}
}

func TestBasetenDecisionWireAndUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/systemone" || r.Header.Get("Authorization") != "Bearer test" || r.Header.Get("S1-Region") != "" {
			t.Error("incorrect decision path, credentials or region header")
		}
		var wire map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		if _, ok := wire["images"]; ok {
			t.Error("text request sent an images field Baseten does not accept")
		}
		var questions map[string]decide.Question
		var model string
		_ = json.Unmarshal(wire["questions"], &questions)
		_ = json.Unmarshal(wire["model"], &model)
		if model != basetenMammoth || questions["red"].Type != "noul" || len(questions) != 3 {
			t.Error("lost model or typed questions")
		}
		_, _ = w.Write([]byte(basetenDecisionBody))
	}))
	defer server.Close()
	client := &openAICompatibleClient{provider: "baseten", baseURL: server.URL + "/v1", apiKey: "test", httpc: server.Client()}
	req := basetenDecideRequest()
	response, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: "baseten", UpstreamModel: basetenMammoth})
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
	if response.InputTokens != 231 || response.OutputTokens != 3 || req.Questions["red"].Type != decide.TypeBoolean {
		t.Fatalf("bad usage or request mutation: %+v", response)
	}
}

func TestBasetenDecisionRefusesUnreviewedModelBeforeCalling(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer server.Close()
	client := &openAICompatibleClient{provider: "baseten", baseURL: server.URL + "/v1", apiKey: "test", httpc: server.Client()}
	for _, model := range []string{"decision-models/baseten-future", "moonshotai/Kimi-K3"} {
		_, err := client.InvokeDecide(context.Background(), &DecideRequest{Model: model}, InvokeOptions{Provider: "baseten", UpstreamModel: model})
		if DecideErrorClass(err) != DecideErrConfig {
			t.Fatalf("%s: unreviewed model was not refused: %v", model, err)
		}
	}
	if calls != 0 {
		t.Fatalf("paid call made for an unreviewed model: %d", calls)
	}
}

func TestBasetenDecisionRejectsWrongModelAndUsage(t *testing.T) {
	for _, body := range []string{
		`{"model":"decision-models/baseten-joey-2b-latest","answers":{},"usage":{"input_tokens":62,"output_tokens":1}}`,
		`{"model":"decision-models/baseten-mammoth-27b-latest","answers":{}}`,
		`{"model":"decision-models/baseten-mammoth-27b-latest","answers":{},"usage":{"input_tokens":62}}`,
		`{"model":"decision-models/baseten-mammoth-27b-latest","answers":{},"usage":{"input_tokens":0,"output_tokens":1}}`,
		`{"model":"decision-models/baseten-mammoth-27b-latest","answers":{},"usage":{"input_tokens":-1,"output_tokens":1}}`,
		`{"model":"decision-models/baseten-mammoth-27b-latest","answers":{},"usage":{"input_tokens":62,"output_tokens":-1}}`,
		`{"model":"decision-models/baseten-mammoth-27b-latest","answers":{},"usage":{"input_tokens":62,"output_tokens":false}}`,
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			client := &openAICompatibleClient{provider: "baseten", baseURL: server.URL, apiKey: "test", httpc: server.Client()}
			_, err := client.InvokeDecide(context.Background(), &DecideRequest{Model: basetenMammoth})
			if DecideErrorClass(err) != DecideErrDecode {
				t.Fatalf("ambiguous response accepted: %v", err)
			}
		})
	}
}

func TestBasetenDecisionBYOKUsesCustomerKeyOnBasetenHost(t *testing.T) {
	calls := 0
	client := &openAICompatibleClient{provider: "baseten", baseURL: directBaseURL("baseten"), apiKey: "operator-key",
		httpc: &http.Client{Transport: regoloDecisionTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.String() != "https://inference.baseten.co/v1/systemone" || r.Header.Get("Authorization") != "Bearer customer-key" {
				t.Error("BYOK used the wrong provider endpoint or credential")
			}
			rec := httptest.NewRecorder()
			_, _ = rec.WriteString(basetenDecisionBody)
			return rec.Result(), nil
		})}}
	_, err := client.InvokeDecide(context.Background(), basetenDecideRequest(), InvokeOptions{
		Provider: "baseten", UpstreamModel: basetenMammoth, UsageType: "BYOK", ProviderAPIKey: "customer-key",
	})
	if err != nil || calls != 1 || client.apiKey != "operator-key" {
		t.Fatalf("BYOK failed: class=%s calls=%d", DecideErrorClass(err), calls)
	}
}
