//go:build llm_multi

package llm

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

const tinfoilDecisionReply = `{"model":"decision-small","answers":[
 {"name":"refund","type":"predicate","probability":0.97},
 {"name":"route","type":"choice","choice":"billing","probabilities":[{"value":"billing","probability":0.96},{"value":"shipping","probability":0.04}]},
 {"name":"urgency","type":"score","score":0.8,"probabilities":[{"value":0,"label":"low","probability":0.2},{"value":1,"label":"high","probability":0.8}]}],
 "usage":{"input_tokens":307,"output_tokens":0,"total_tokens":307}}`

func tinfoilDecisionClient(t *testing.T, reply string) *openAICompatibleClient {
	t.Helper()
	client := newTinfoilAttested("synthetic-key")
	client.httpcGetter = func() (*http.Client, error) {
		return &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://inference.tinfoil.sh/v1/decisions" || r.Header.Get("Authorization") != "Bearer synthetic-key" {
				t.Fatal("decision request escaped verified authority")
			}
			var wire map[string]any
			if json.NewDecoder(r.Body).Decode(&wire) != nil || wire["model"] != "decision-small" || wire["input"] != "charged twice" || wire["state"] != nil {
				t.Fatal("wrong native wire format")
			}
			questions := wire["questions"].([]any)
			predicate := questions[0].(map[string]any)
			choice := questions[1].(map[string]any)
			score := questions[2].(map[string]any)
			if predicate["type"] != "predicate" || !strings.Contains(predicate["instructions"].(string), "asks for money back") || !strings.Contains(choice["instructions"].(string), "charges") || len(choice["choices"].([]any)) != 2 || len(score["levels"].([]any)) != 2 {
				t.Fatal("question semantics lost in translation")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(reply))}, nil
		})}, nil
	}
	return client
}

func TestTinfoilDecisionsVerifiedDispatchAndUsage(t *testing.T) {
	req, specs := hostedRequest(t)
	req.Model = "tinfoil/decision-small"
	multi := &multiClient{tinfoil: tinfoilDecisionClient(t, tinfoilDecisionReply)}
	response, err := multi.InvokeDecide(t.Context(), req, InvokeOptions{Provider: "tinfoil", UpstreamModel: "decision-small"})
	if err != nil {
		t.Fatal(err)
	}
	if response.InputTokens != 307 || response.OutputTokens != 0 {
		t.Fatal("wrong billable usage")
	}
	if _, err := decide.Verify(specs, response.Answers); err != nil {
		t.Fatal(err)
	}
}

func TestTinfoilDecisionsFailClosed(t *testing.T) {
	req, _ := hostedRequest(t)
	for _, failure := range []string{"no-client", "no-getter", "nil-client", "verifier-error", "wrong-provider"} {
		t.Run(failure, func(t *testing.T) {
			client := newTinfoilAttested("synthetic-key")
			plain := &http.Client{Transport: byokRoundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unverified transport used"); return nil, nil })}
			client.httpc = plain
			client.httpcGetter = func() (*http.Client, error) { return nil, nil }
			options := InvokeOptions{Provider: "tinfoil", UpstreamModel: "decision-small"}
			switch failure {
			case "no-getter":
				client.httpcGetter = nil
			case "verifier-error":
				client.httpcGetter = func() (*http.Client, error) { return nil, errors.New("private verification detail") }
			case "wrong-provider":
				client.provider = "typesafe"
				client.httpcGetter = func() (*http.Client, error) { return plain, nil }
			}
			multi := &multiClient{tinfoil: client}
			if failure == "no-client" {
				multi.tinfoil = nil
			}
			_, err := multi.InvokeDecide(t.Context(), req, options)
			if DecideErrorClass(err) != DecideErrConfig || strings.Contains(err.Error(), "private verification detail") {
				t.Fatalf("did not fail closed: %v", err)
			}
		})
	}
}

func TestTinfoilDecisionsRefuseMalformedAccountingAndAnswers(t *testing.T) {
	req, specs := hostedRequest(t)
	for _, change := range [][2]string{
		{`"model":"decision-small"`, `"model":"decision-large"`},
		{`"input_tokens":307`, `"input_tokens":null`},
		{`"input_tokens":307`, `"input_tokens":-1`},
		{`"input_tokens":307`, `"input_tokens":3.5`},
		{`"output_tokens":0`, `"output_tokens":1`},
		{`"output_tokens":0`, `"output_tokens":null`},
		{`"total_tokens":307`, `"total_tokens":306`},
		{`"total_tokens":307`, `"total_tokens":null`},
		{`"name":"route"`, `"name":"refund"`},
		{`"value":"shipping"`, `"value":"billing"`},
		{`"value":1`, `"value":0`},
		{`"value":1`, `"value":null`},
		{`"probability":0.04`, `"probability":null`},
		{`"type":"predicate"`, `"type":"boolean"`},
		{`"probability":0.97`, `"probability":0.97,"choice":"oops"`},
		{`"probability":0.97`, `"probability":0.97,"probability":0.2`},
		{`"name":"refund"`, `"name":"unknown"`},
	} {
		reply := strings.Replace(tinfoilDecisionReply, change[0], change[1], 1)
		client := tinfoilDecisionClient(t, reply)
		response, err := client.InvokeDecide(t.Context(), req, InvokeOptions{Provider: "tinfoil", UpstreamModel: "decision-small"})
		if err == nil {
			_, err = decide.Verify(specs, response.Answers)
		}
		if err == nil {
			t.Fatalf("accepted malformed response: %s", change[1])
		}
	}
}
