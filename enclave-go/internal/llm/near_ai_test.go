package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type nearAITestConnection struct {
	fingerprint string
	dials       int32
	closed      atomic.Bool
}

func (c *nearAITestConnection) Fingerprint() (string, error) {
	if c.fingerprint == "" {
		return "", errors.New("missing fingerprint")
	}
	return c.fingerprint, nil
}

func (c *nearAITestConnection) Dials() int32          { return c.dials }
func (c *nearAITestConnection) CloseIdleConnections() { c.closed.Store(true) }

type nearAIRoundTripper func(*http.Request) (*http.Response, error)

func (fn nearAIRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func nearAITestClient(t *testing.T, verifyError error, dials int32) (*nearAIClient, *atomic.Int32) {
	t.Helper()
	const (
		domain      = "glm-5-2.completions.near.ai"
		nonce       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	requests := &atomic.Int32{}
	connection := &nearAITestConnection{fingerprint: fingerprint, dials: dials}
	httpc := &http.Client{Transport: nearAIRoundTripper(func(request *http.Request) (*http.Response, error) {
		call := requests.Add(1)
		if call == 1 {
			if request.Method != http.MethodGet || request.URL.Host != domain ||
				request.URL.Query().Get("nonce") != nonce ||
				request.URL.Query().Get("include_tls_fingerprint") != "true" ||
				request.URL.Query().Get("signing_algo") != "ed25519" {
				t.Errorf("unexpected attestation request: %s %s", request.Method, request.URL.String())
			}
			if request.Header.Get("Authorization") != "Bearer operator-key" {
				t.Errorf("attestation authorization = %q", request.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"attestation":"evidence"}`)),
				Request:    request,
			}, nil
		}
		if call != 2 {
			t.Errorf("unexpected request count %d", call)
		}
		if request.Method != http.MethodPost || request.URL.Host != domain || request.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected inference request: %s %s", request.Method, request.URL.String())
		}
		body, _ := io.ReadAll(request.Body)
		if !bytes.Contains(body, []byte("private prompt")) {
			t.Errorf("inference body omitted prompt: %s", body)
		}
		stream := "data: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"PONG\"},\"finish_reason\":null}]}\n\n" +
			"data: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":3}}\n\n" +
			"data: [DONE]\n\n"
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader(stream)),
			Request:    request,
		}, nil
	})}
	client := newNearAI("operator-key")
	client.newNonce = func() (string, error) { return nonce, nil }
	client.openConnection = func(gotDomain string) (nearAIConnection, *http.Client, error) {
		if gotDomain != domain {
			t.Errorf("direct domain = %q", gotDomain)
		}
		return connection, httpc, nil
	}
	client.verifyEvidence = func(_ context.Context, envelope *nearAIEvidenceEnvelope) (*nearAIVerificationResult, error) {
		if requests.Load() != 1 {
			t.Errorf("verification ran after %d upstream calls, want attestation only", requests.Load())
		}
		if envelope.Model != "z-ai/glm-5.2" || envelope.Domain != domain || envelope.Nonce != nonce ||
			envelope.TLSFingerprint != fingerprint || !json.Valid(envelope.Evidence) {
			t.Errorf("unexpected evidence envelope: %#v", envelope)
		}
		if verifyError != nil {
			return nil, verifyError
		}
		now := time.Now()
		return &nearAIVerificationResult{
			VerifiedAt: now, ExpiresAt: now.Add(time.Minute), Policy: "near-ai-tdx-nvidia-direct-v1",
		}, nil
	}
	return client, requests
}

func invokeNearAITestClient(client *nearAIClient, out io.Writer) error {
	return client.InvokeStreaming(
		context.Background(),
		&qtypes.OpenAIChatRequest{Model: "z-ai/glm-5.2"},
		&qtypes.AnthropicMessagesRequest{
			Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "private prompt"}},
		},
		out,
		InvokeOptions{Provider: "near-ai", UpstreamModel: "z-ai/glm-5.2"},
	)
}

func TestNearAIClientAttestsSameConnectionBeforeSendingPrompt(t *testing.T) {
	client, requests := nearAITestClient(t, nil, 1)
	var output bytes.Buffer
	if err := invokeNearAITestClient(client, &output); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("upstream requests = %d, want attestation plus inference", requests.Load())
	}
	if !strings.Contains(output.String(), "PONG") {
		t.Fatalf("translated response omitted PONG: %s", output.String())
	}
}

func TestNearAIClientNeverSendsPromptWhenAttestationFails(t *testing.T) {
	client, requests := nearAITestClient(t, errors.New("attestation rejected"), 1)
	if err := invokeNearAITestClient(client, io.Discard); err == nil || !strings.Contains(err.Error(), "attestation rejected") {
		t.Fatalf("attestation error = %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("upstream requests = %d, prompt was sent after failed attestation", requests.Load())
	}
}

func TestNearAIClientRefusesConnectionChangeBeforePrompt(t *testing.T) {
	client, requests := nearAITestClient(t, nil, 2)
	if err := invokeNearAITestClient(client, io.Discard); err == nil || !strings.Contains(err.Error(), "connection changed") {
		t.Fatalf("connection-change error = %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("upstream requests = %d, prompt was sent after connection change", requests.Load())
	}
}

func TestNearAIClientRejectsUnknownModelsAndBYOKCannotBypassAttestation(t *testing.T) {
	client := newNearAI("operator-key")
	err := client.InvokeStreaming(
		context.Background(),
		&qtypes.OpenAIChatRequest{Model: "attacker/model"},
		&qtypes.AnthropicMessagesRequest{},
		io.Discard,
		InvokeOptions{Provider: "near-ai", UpstreamModel: "attacker/model", ProviderAPIKey: "user-key"},
	)
	if err == nil || !strings.Contains(err.Error(), "no pinned direct attested endpoint") {
		t.Fatalf("unknown model error = %v", err)
	}
	if isOpenAICompatibleBYOKProvider("near-ai") {
		t.Fatal("NEAR AI must never use the generic BYOK adapter")
	}
	if got := directModelID("near-ai", "attacker/model", "attacker/model"); got != "" {
		t.Fatalf("unknown NEAR AI model resolved to %q, want fail-closed empty id", got)
	}
}

func TestNearAISingleConnectionRejectsUnpinnedDomainsAndRedials(t *testing.T) {
	for _, domain := range []string{"near.ai", "GLM-5-2.completions.near.ai", "x.completions.near.ai:443"} {
		if _, _, err := newNearAISingleConnection(domain); err == nil {
			t.Fatalf("invalid domain %q accepted", domain)
		}
	}
	connection, _, err := newNearAISingleConnection("glm-5-2.completions.near.ai")
	if err != nil {
		t.Fatal(err)
	}
	connection.dials.Store(1)
	if _, err := connection.dialTLS(context.Background(), "tcp", connection.expected); err == nil ||
		!strings.Contains(err.Error(), "refusing unverified redial") {
		t.Fatalf("redial error = %v", err)
	}
	if _, err := connection.dialTLS(context.Background(), "tcp", "attacker.invalid:443"); err == nil ||
		!strings.Contains(err.Error(), "unexpected TLS endpoint") {
		t.Fatalf("unexpected endpoint error = %v", err)
	}
}

func TestNearAIPinnedModelDomainAndSidecarPoliciesStayInSync(t *testing.T) {
	if len(nearAIModelMap) != len(nearAIDirectDomains) {
		t.Fatalf("model map has %d rows, domain map has %d", len(nearAIModelMap), len(nearAIDirectDomains))
	}
	raw, err := os.ReadFile("../../sidecar/near_ai_policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var policies []struct {
		Model  string `json:"model"`
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(raw, &policies); err != nil {
		t.Fatal(err)
	}
	policyDomains := make(map[string]string, len(policies))
	for _, policy := range policies {
		policyDomains[policy.Model] = policy.Domain
	}
	for canonical, upstream := range nearAIModelMap {
		domain := nearAIDirectDomains[upstream]
		if domain == "" {
			t.Errorf("%s maps to %s without a direct domain", canonical, upstream)
			continue
		}
		if policyDomains[upstream] != domain {
			t.Errorf("%s policy domain = %q, want %q", upstream, policyDomains[upstream], domain)
		}
		delete(policyDomains, upstream)
	}
	if len(policyDomains) != 0 {
		t.Fatalf("sidecar has policies without inference mappings: %v", policyDomains)
	}
}
