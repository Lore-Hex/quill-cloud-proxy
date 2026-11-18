package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// lenientControlPlane authorizes and settles one request and answers key
// validation with the configured lenient setting.
type lenientControlPlane struct {
	keyLenient, invalidKey              bool
	authorize, settle, validate, probes atomic.Int32
	requestedParameters, unknown        atomic.Value
}

func (c *lenientControlPlane) serve(t *testing.T) *httptest.Server {
	t.Helper()
	// Each test starts with no remembered key settings.
	previous := keyLenience
	keyLenience = &keyLenienceCache{entries: map[string]keyLenienceEntry{}}
	t.Cleanup(func() { keyLenience = previous })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "private-value") {
			t.Errorf("request value reached control plane at %s", r.URL.Path)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			c.authorize.Add(1)
			c.requestedParameters.Store(string(body))
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_lenient","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/settle":
			c.settle.Add(1)
			_, _ = io.WriteString(w, `{"data":{"settled":true,"generation_id":"gen_lenient","cost_microdollars":12,"model":"openai/gpt-4o-mini","provider":"openai","region":"us-central1"}}`)
		case "/internal/gateway/validate":
			c.validate.Add(1)
			// The failure path's own attribution lookup is not a probe.
			if strings.Contains(string(body), `"lenience_probe":true`) {
				c.probes.Add(1)
			}
			if c.invalidKey {
				w.WriteHeader(401)
				_, _ = io.WriteString(w, `{"error":{"message":"Invalid API key"}}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1","lenient":%t}}`, c.keyLenient)
		default:
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func serveLenientRequest(t *testing.T, control *httptest.Server, route, bearer, extraHeaders, body string) (*http.Response, string, *fakeStreamingLLM, string) {
	t.Helper()
	request := fmt.Sprintf("POST %s HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s", route, bearer, extraHeaders, len(body), body)
	conn := newScriptedConn(request, nil)
	provider := &fakeStreamingLLM{}
	logs := captureProviderStreamStderr(t, func() *providerInvocation {
		serveOne(context.Background(), conn, auth.New(nil), provider, nil, nil, trustedrouter.New(control.URL, "internal-test", control.Client()), nil)
		return nil
	})
	response, responseBody := readRawHTTPResponse(t, conn.writes.Bytes())
	return response, string(responseBody), provider, logs
}

const lenientChatBody = `{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"temperature":0.1,"extra_body":{"secret":"private-value"},"safety_settings":[],"provider":{"quantizations":["fp8"]},"route":"fallback"}`

func TestLenientHeaderDropsParametersAndNamesThem(t *testing.T) {
	plane := &lenientControlPlane{}
	control := plane.serve(t)
	response, body, provider, logs := serveLenientRequest(t, control, "/v1/chat/completions", "sk-lenient-header", "X-TrustedRouter-Lenient: true\r\n", lenientChatBody)
	if response.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", response.StatusCode, body)
	}
	ignored := response.Header.Get(ignoredParametersHeader)
	for _, name := range []string{"extra_body", "safety_settings", "provider.quantizations", "route"} {
		if !strings.Contains(ignored, name) {
			t.Fatalf("ignored header %q is missing %s", ignored, name)
		}
	}
	if provider.request == nil || provider.request.Temperature == nil || *provider.request.Temperature != 0.1 {
		t.Fatal("supported parameters did not reach the provider")
	}
	if plane.probes.Load() != 1 || plane.validate.Load() != 1 {
		t.Fatalf("a request-level opt-in verified the key %d times (%d probes); want one probe", plane.validate.Load(), plane.probes.Load())
	}
	if strings.Contains(logs, "extra_body") || strings.Contains(logs, "private-value") {
		t.Fatalf("lenient drop logged client-chosen names: %s", logs)
	}
	if !strings.Contains(logs, "enclave.lenient_drop") {
		t.Fatal("lenient drop was not counted in the log")
	}
}

func TestLenientKeySettingDropsParameters(t *testing.T) {
	plane := &lenientControlPlane{keyLenient: true}
	control := plane.serve(t)
	bearer := "sk-lenient-key-setting" // #nosec G101 -- test bearer, not a credential.
	for i := 0; i < 2; i++ {
		response, body, _, _ := serveLenientRequest(t, control, "/v1/chat/completions", bearer, "", lenientChatBody)
		if response.StatusCode != 200 {
			t.Fatalf("status = %d body=%s", response.StatusCode, body)
		}
		if response.Header.Get(ignoredParametersHeader) == "" {
			t.Fatal("ignored parameters header missing")
		}
	}
	if got := plane.probes.Load(); got != 1 || plane.validate.Load() != 1 {
		t.Fatalf("key setting looked up %d times; want one cached lookup", got)
	}
}

func TestStrictKeyStillRefusesUnknownParameters(t *testing.T) {
	plane := &lenientControlPlane{}
	control := plane.serve(t)
	response, body, provider, _ := serveLenientRequest(t, control, "/v1/chat/completions", "sk-strict-key", "", lenientChatBody)
	// The body holds both unknown (400) and unsupported (501) parameters;
	// which one is reported first follows map order.
	if response.StatusCode != 400 && response.StatusCode != 501 {
		t.Fatalf("status = %d body=%s", response.StatusCode, body)
	}
	if response.Header.Get(ignoredParametersHeader) != "" {
		t.Fatal("strict refusal carried an ignored parameters header")
	}
	if provider.request != nil || plane.authorize.Load() != 0 {
		t.Fatal("strict refusal reached authorize or the provider")
	}
}

func TestStrictRequestPaysNoKeyLookup(t *testing.T) {
	plane := &lenientControlPlane{}
	control := plane.serve(t)
	clean := `{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	response, body, _, _ := serveLenientRequest(t, control, "/v1/chat/completions", "sk-clean", "", clean)
	if response.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", response.StatusCode, body)
	}
	if plane.validate.Load() != 0 || response.Header.Get(ignoredParametersHeader) != "" {
		t.Fatal("a request with nothing to drop paid for lenient mode")
	}
}

func TestLenientModeKeepsValueErrors(t *testing.T) {
	plane := &lenientControlPlane{}
	control := plane.serve(t)
	bad := `{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"extra_body":{},"store":"yes"}`
	response, body, _, _ := serveLenientRequest(t, control, "/v1/chat/completions", "sk-bad-value", "X-TrustedRouter-Lenient: 1\r\n", bad)
	if response.StatusCode != 400 || !strings.Contains(body, "store must be a boolean") {
		t.Fatalf("status = %d body=%s", response.StatusCode, body)
	}
}

func TestLenientResponsesRoute(t *testing.T) {
	plane := &lenientControlPlane{}
	control := plane.serve(t)
	body := `{"model":"openai/gpt-4o-mini","input":"hi","made_up":{"a":1},"store":true,"provider":{"quantizations":["int4"]}}`
	response, responseBody, _, _ := serveLenientRequest(t, control, "/v1/responses", "sk-lenient-responses", "X-TrustedRouter-Lenient: on\r\n", body)
	if response.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", response.StatusCode, responseBody)
	}
	ignored := response.Header.Get(ignoredParametersHeader)
	for _, name := range []string{"made_up", "store", "provider.quantizations"} {
		if !strings.Contains(ignored, name) {
			t.Fatalf("ignored header %q is missing %s", ignored, name)
		}
	}
}

func TestIgnoredParametersHeaderValueIsHeaderSafe(t *testing.T) {
	value := ignoredParametersHeaderValue([]string{"a\r\nInjected: 1", "b,c", "é"})
	if strings.ContainsAny(value, "\r\n") || value != "a??Injected: 1, b?c, ?" {
		t.Fatalf("value = %q", value)
	}
	long := make([]string, 200)
	for i := range long {
		long[i] = strings.Repeat("x", 20)
	}
	if got := ignoredParametersHeaderValue(long); len(got) > maxIgnoredParametersHeaderBytes+5 || !strings.HasSuffix(got, "...") {
		t.Fatalf("long value not capped: %d bytes", len(got))
	}
}

func TestLenientHeaderSplitsTheBillingBackoffKey(t *testing.T) {
	strict := billingBackoffHeaderGroups(requestAttributionHeaders{}, false)
	lenient := billingBackoffHeaderGroups(requestAttributionHeaders{Lenient: true}, false)
	if fmt.Sprint(strict) == fmt.Sprint(lenient) {
		t.Fatal("lenient and strict requests share a billing backoff key")
	}
}

func TestBrowserClientsCanReadIgnoredParameters(t *testing.T) {
	if !strings.Contains(strings.ToLower(bearerCORSResponseHeaders), ignoredParametersHeader) {
		t.Fatal("ignored parameters header is not exposed to browser clients")
	}
}

// adapter.ToAnthropic refuses a non-function tool_choice after authorization.
// A lenient request drops it before any credit is held; a strict one keeps
// its existing answer from that later stage.
func TestLenientDropsAnUnsupportedToolChoiceBeforeAuthorization(t *testing.T) {
	body := `{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}],"tool_choice":{"type":"code_interpreter"}}`

	lenientPlane := &lenientControlPlane{}
	response, responseBody, provider, _ := serveLenientRequest(t, lenientPlane.serve(t), "/v1/chat/completions", "sk-lenient-tool-choice", "X-TrustedRouter-Lenient: true\r\n", body)
	if response.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", response.StatusCode, responseBody)
	}
	if got := response.Header.Get(ignoredParametersHeader); got != "tool_choice" {
		t.Fatalf("ignored = %q", got)
	}
	if provider.request == nil || len(provider.request.Tools) != 1 {
		t.Fatal("the supported function tool did not reach the provider")
	}

	strictPlane := &lenientControlPlane{}
	response, responseBody, _, _ = serveLenientRequest(t, strictPlane.serve(t), "/v1/chat/completions", "sk-strict-tool-choice", "", body)
	if response.StatusCode != 501 {
		t.Fatalf("strict status = %d body=%s", response.StatusCode, responseBody)
	}
	if response.Header.Get(ignoredParametersHeader) != "" {
		t.Fatal("strict refusal carried an ignored parameters header")
	}
}

func TestLaterChatChecksLeaveSupportedChoicesAlone(t *testing.T) {
	for _, choice := range []any{
		nil,
		"auto",
		map[string]any{"type": "function", "function": map[string]any{"name": "f"}},
		map[string]any{"type": "trustedrouter:subagent"},
	} {
		if err := laterChatChecks(&types.OpenAIChatRequest{ToolChoice: choice}); err != nil {
			t.Fatalf("%v: %v", choice, err)
		}
	}
	// A hosted search choice with no search tool is never normalized, so the
	// later stage would refuse it.
	for _, choiceType := range []string{"code_interpreter", "web_search", " function "} {
		err := laterChatChecks(&types.OpenAIChatRequest{ToolChoice: map[string]any{"type": choiceType}})
		if path, ok := adapter.LenientDropPath(err); !ok || path != "tool_choice" {
			t.Fatalf("%s: %v", choiceType, err)
		}
	}
}

// A request-level opt-in from a key the control plane does not accept gets
// the strict answer: unauthenticated callers cannot make the gateway re-parse.
func TestLenientHeaderNeedsAVerifiedKey(t *testing.T) {
	plane := &lenientControlPlane{invalidKey: true}
	response, body, provider, _ := serveLenientRequest(t, plane.serve(t), "/v1/chat/completions", "sk-unknown-key", "X-TrustedRouter-Lenient: true\r\n", lenientChatBody)
	if response.StatusCode != 400 && response.StatusCode != 501 {
		t.Fatalf("status = %d body=%s", response.StatusCode, body)
	}
	if response.Header.Get(ignoredParametersHeader) != "" || provider.request != nil {
		t.Fatal("an unverified key's request was parsed leniently")
	}
}
