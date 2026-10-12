//go:build llm_multi

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

const azureDecisionReply = `{"model":"microsoft-decision-1","answers":{
 "refund":{"type":"noul","noul":0.97},
 "route":{"type":"choice","choice":"billing","probabilities":{"billing":0.96,"shipping":0.04}},
 "urgency":{"type":"score","score":0.8,"probabilities":{"0":0.2,"1":0.8}}},
 "usage":{"input_tokens":93,"output_tokens":3}}`

func TestAzureDecideDispatchAndWire(t *testing.T) {
	req, specs := hostedRequest(t)
	req.Model = "microsoft/microsoft-decision-1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/providers/microsoft/v1/systemone" || r.Method != http.MethodPost {
			t.Errorf("wrong decision endpoint: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("api-key") != "test-key" || r.Header.Get("Authorization") != "" {
			t.Error("wrong Azure authentication")
		}
		var body DecideRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Model != "tr-decision-1" || body.Questions["refund"].Type != "noul" || string(body.State) != string(req.State) {
			t.Error("wrong model, state or question translation")
		}
		_, _ = io.WriteString(w, azureDecisionReply)
	}))
	defer server.Close()
	client := newAzure("test-key")
	client.decision.baseURL = server.URL + "/providers/microsoft/v1"
	multi := &multiClient{azure: client}
	response, err := multi.InvokeDecide(context.Background(), req, InvokeOptions{Provider: "azure", UpstreamModel: "tr-decision-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decide.Verify(specs, response.Answers); err != nil {
		t.Fatal(err)
	}
	if response.InputTokens != 93 || response.OutputTokens != 3 || !decide.IsHostedModel(req.Model) {
		t.Fatalf("wrong usage or hosted identity: %+v", response)
	}
}

func TestAzureDecideRejectsWrongUsageAndModel(t *testing.T) {
	for _, replacement := range []struct{ from, to string }{
		{`"input_tokens":93`, `"input_tokens":0`},
		{`"input_tokens":93`, `"input_tokens":-1`},
		{`"output_tokens":3`, `"output_tokens":null`},
		{`"output_tokens":3`, `"output_tokens":-1`},
		{`"model":"microsoft-decision-1"`, `"model":"another-model"`},
	} {
		t.Run(replacement.to, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, strings.Replace(azureDecisionReply, replacement.from, replacement.to, 1))
			}))
			defer server.Close()
			req, _ := hostedRequest(t)
			_, err := invokeSystemOne(context.Background(), server.Client(), "azure", server.URL, "key", "tr-decision-1", req)
			if DecideErrorClass(err) != DecideErrDecode {
				t.Fatalf("accepted wrong usage/identity: %v", err)
			}
		})
	}
}

func TestAzureDecideRejectsRedirectAndUnsupportedRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://credential-leak.invalid/", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := newAzure("test-key")
	client.decision.baseURL = server.URL
	req, _ := hostedRequest(t)
	req.Model = "microsoft/microsoft-decision-1"
	option := InvokeOptions{Provider: "azure", UpstreamModel: "tr-decision-1"}
	_, err := client.InvokeDecide(context.Background(), req, option)
	if status, ok := DecideErrorStatus(err); !ok || status != http.StatusTemporaryRedirect {
		t.Fatalf("redirect followed: %v", err)
	}
	option.UpstreamModel = "unapproved-deployment"
	_, err = client.InvokeDecide(context.Background(), req, option)
	if DecideErrorClass(err) != DecideErrConfig {
		t.Fatal("unapproved deployment was accepted")
	}
	option.UpstreamModel = "tr-decision-1"
	req.Images = []string{"https://example.com/image.png"}
	_, err = client.InvokeDecide(context.Background(), req, option)
	if DecideErrorClass(err) != DecideErrConfig {
		t.Fatal("images were accepted")
	}
	multi := &multiClient{}
	_, err = multi.InvokeDecide(context.Background(), req, option)
	if DecideErrorClass(err) != DecideErrConfig {
		t.Fatal("missing Azure bootstrap key was accepted")
	}
}
