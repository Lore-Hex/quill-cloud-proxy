package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowcoord"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speculation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type shadowCountingProvider struct {
	calls    atomic.Int32
	ordinary fakeStreamingLLM
}

func (p *shadowCountingProvider) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, a *types.AnthropicMessagesRequest, w io.Writer, opts ...llm.InvokeOptions) error {
	p.calls.Add(1)
	return p.ordinary.InvokeStreaming(ctx, req, a, w, opts...)
}
func TestShadowPhysicalMoneyOutputDifferential(t *testing.T) {
	var outputs []string
	for _, mode := range []shadowcoord.Mode{shadowcoord.Off, shadowcoord.Shadow} {
		var authorize, settle, refund, heartbeat atomic.Int32
		control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/internal/gateway/authorize":
				authorize.Add(1)
				_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_shadow","workspace_id":"w","api_key_hash":"k","model":"fixture-text","upstream_model":"fixture-text","endpoint_id":"ep1","provider":"fixture-provider","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
			case "/internal/gateway/settle":
				settle.Add(1)
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if body["actual_input_tokens"] != float64(2) || body["actual_output_tokens"] != float64(2) {
					t.Errorf("changed money payload %v", body)
				}
				_, _ = io.WriteString(w, `{"data":{"settled":true,"generation_id":"gen_shadow","cost_microdollars":5,"model":"fixture-text","provider":"fixture-provider"}}`)
			case "/internal/gateway/refund":
				refund.Add(1)
				_, _ = io.WriteString(w, `{"data":{}}`)
			case "/internal/gateway/usage-heartbeat":
				heartbeat.Add(1)
				_, _ = io.WriteString(w, `{"data":{}}`)
			default:
				_, _ = io.WriteString(w, `{"data":{"workspace_id":"w","api_key_hash":"k"}}`)
			}
		}))
		gateway := trustedrouter.New(control.URL, "internal", control.Client())
		ctx, cancel := context.WithCancel(t.Context())
		if mode == shadowcoord.Shadow {
			observer := literalShadowCoordinator(t)
			gateway.ConfigureSpeculation(ctx, observer)
			ctx, _ = trustedrouter.WithAPIKeyLookupHash(ctx, strings.Repeat("a", 64))
		} else {
			gateway.ConfigureSpeculation(ctx, nil)
		}
		body := `{"model":"fixture-text","messages":[{"role":"user","content":"private-prompt"}],"stream":true,"max_tokens":128,"provider":{"usage":"Credits"}}`
		conn := newScriptedConn(fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer test-key\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body), nil)
		provider := &shadowCountingProvider{}
		serveOne(ctx, conn, auth.New(nil), provider, nil, nil, gateway, nil)
		if authorize.Load() != 1 || settle.Load() != 1 || refund.Load() != 0 || heartbeat.Load() != 0 || provider.calls.Load() != 1 {
			t.Fatalf("mode=%s authorize=%d settle=%d refund=%d heartbeat=%d physical=%d output=%s", mode, authorize.Load(), settle.Load(), refund.Load(), heartbeat.Load(), provider.calls.Load(), conn.writes.String())
		}
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(conn.writes.Bytes())), nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		output := stageDChatFixtureID.ReplaceAllString(string(raw), `"id":"fixed"`)
		output = stageDCreatedField.ReplaceAllString(output, `"created":0`)
		// Existing public timing is variable; compare the full remaining SSE bytes.
		output = regexp.MustCompile(`"(ttfb_ms|route_ms|authorize_ms|upstream_ms|settle_ms|elapsed_ms|total_ms)":\s*[0-9.]+`).ReplaceAllString(output, `"$1":0`)
		outputs = append(outputs, output)
		if mode == shadowcoord.Shadow {
			var execution shadowcoord.Record
			for len(gateway.Speculation().Records()) > 0 {
				r := <-gateway.Speculation().Records()
				if r.Kind == "execution" {
					execution = r
				}
			}
			if execution.Decision == nil || !execution.Decision.Eligible || execution.AuthorizationID != "auth_shadow" || execution.MeasuredP == nil {
				t.Fatal("self qualified", execution)
			}
		}
		cancel()
		control.Close()
	}
	if outputs[0] != outputs[1] {
		t.Fatalf("output changed\noff %s\nshadow %s", outputs[0], outputs[1])
	}
}

type shadowGuard struct{ deny bool }

func (g *shadowGuard) BeforeCredentialCheck(context.Context, string) error {
	if g.deny {
		return &trustedrouter.ControlPlaneError{StatusCode: 401, Type: "invalid_api_key", Message: "rejected"}
	}
	return nil
}
func (*shadowGuard) AfterCredentialCheck(context.Context, string, error) {}
func TestShadowCredentialBackoffOrderingCounters(t *testing.T) {
	var calls atomic.Int32
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/gateway/authorize" {
			calls.Add(1)
			w.WriteHeader(402)
			_, _ = io.WriteString(w, `{"error":{"type":"insufficient_credits","message":"no credits"}}`)
		} else {
			_, _ = io.WriteString(w, `{"data":{"workspace_id":"w","api_key_hash":"k"}}`)
		}
	}))
	defer control.Close()
	gateway := trustedrouter.New(control.URL, "internal", control.Client())
	guard := &shadowGuard{}
	gateway.SetCredentialGuard(guard)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	gateway.ConfigureSpeculation(ctx, shadowcoord.New(shadowcoord.Shadow, shadowcoord.Config{}, nil))
	body := `{"model":"fixture-text","messages":[{"role":"user","content":"secret"}]}`
	request := func() []byte {
		conn := newScriptedConn(fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer key\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body), nil)
		serveOne(ctx, conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
		return conn.writes.Bytes()
	}
	first := request()
	second := request()
	third := request()
	if !bytes.Equal(first, second) || !bytes.Equal(first, third) || calls.Load() != 1 {
		t.Fatal("suppression changed response or authorize count")
	}
	guard.deny = true
	if got := request(); !bytes.Contains(got, []byte("401")) {
		t.Fatal("backoff beat credential guard", string(got))
	}
	var decisions, suppressed int
	ids := map[string]bool{}
	denial := ""
	for len(gateway.Speculation().Records()) > 0 {
		r := <-gateway.Speculation().Records()
		if ids[r.ObservationID] {
			t.Fatal("reused observation id")
		}
		ids[r.ObservationID] = true
		switch r.Kind {
		case "predecision":
			decisions++
		case "execution":
			denial = r.DenialID
		case "billing_backoff_suppressed":
			suppressed++
			if r.OriginalDenialID != denial {
				t.Fatal("denial join", r)
			}
		}
	}
	if decisions != 1 || suppressed != 2 {
		t.Fatalf("decisions %d suppressed %d", decisions, suppressed)
	}
}
func TestSpeculationStartupAndProvenance(t *testing.T) {
	t.Setenv("QUILL_SPECULATIVE_PROVIDER_CONFIG", "invalid")
	if initializeSpeculation(t.Context(), nil, shadowcoord.Off) != nil {
		t.Fatal("off read configuration")
	}
	if initializeSpeculation(t.Context(), nil, shadowcoord.Shadow) == nil {
		t.Fatal("invalid configuration")
	}
	for _, raw := range []string{`{"ClockUncertainty":-1}`, `{"Evidence":[` + strings.Repeat(`{},`, 256) + `{}]}`} {
		t.Setenv("QUILL_SPECULATIVE_PROVIDER_CONFIG", raw)
		if initializeSpeculation(t.Context(), nil, shadowcoord.Shadow) == nil {
			t.Fatal("bounds")
		}
	}
	t.Setenv("QUILL_SPECULATIVE_PROVIDER_CONFIG", `{"Evidence":[{"Identity":{"key_id":"k","workspace_id":"w","lookup_digest":"`+strings.Repeat("a", 64)+`"}}]}`)
	ctx, cancel := context.WithCancel(t.Context())
	gateway := trustedrouter.New("http://127.0.0.1:18080", "internal", nil)
	if err := initializeSpeculation(ctx, gateway, shadowcoord.Shadow); err != nil {
		t.Fatal(err)
	}
	gateway.Speculation().Suppressed("original")
	time.Sleep(time.Millisecond)
	cancel()
	req := &types.OpenAIChatRequest{App: "attribution"}
	if shadowobserve.FromContext(predecideSpeculation(t.Context(), gateway, "key", []byte(`{}`), true, "chat.completions", false, req, false)) == nil {
		t.Fatal("missing predecision")
	}
	raw := "POST /v1/chat/completions HTTP/1.1\r\nIdempotency-Key:\r\nContent-Length: 2\r\n\r\n{}"
	_, _, _, _, a, _, err := readRequestWithHeadersRead(bufio.NewReader(strings.NewReader(raw)), nil)
	if err != nil || !a.IdempotencyPresent {
		t.Fatal("empty header presence lost", err)
	}
}

type shadowLiteralClock struct{}

func (shadowLiteralClock) Now() time.Time { return time.Unix(2000, 0) }
func literalShadowCoordinator(t *testing.T) *shadowcoord.Coordinator {
	t.Helper()
	raw, err := os.ReadFile("../../internal/speculation/testdata/speculation_v1/shadow-refresh-wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Keys    []speculation.TrustedKey `json:"trusted_test_keys"`
		Context json.RawMessage          `json:"context"`
		Grant   string                   `json:"grant_jws"`
		Items   []shadowcoord.Identity   `json:"items"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture")
	}
	bindings := shadowcoord.ParseRequest(f.Context)
	route := bindings["route"].(map[string]any)
	cert := speculation.AdapterCertificate{Route: route, BoundAlgorithm: speculation.ConservativeUTF8Bytes, FramingKnown: true, HardOutputCap: true, SingleAttempt: true, NoHiddenTools: true, NoHiddenReasoning: true, VendorPricesBounded: true}
	local := speculation.LocalContext{Bindings: bindings, Certificates: []speculation.AdapterCertificate{cert}, RequestPolicyHash: route["routing_policy_hash"].(string), OwnerBootID: "boot", OwnerBootCount: 1, PilotAllowed: true, PaidProvenance: true, KeyEligible: true, BootVerified: true, PolicyFresh: true, StageDEnabled: true}
	health := speculation.LocalHealth{WorkspaceID: "w", KeyID: "k", Provider: "fixture-provider", Workspace: speculation.ScopeHealth{Known: true, Healthy: true}, Key: speculation.ScopeHealth{Known: true, Healthy: true}, ProviderKnown: true, ProviderHealthy: true, InfrastructureHealthy: true}
	c := shadowcoord.New(shadowcoord.Shadow, shadowcoord.Config{Keys: f.Keys, Evidence: []shadowcoord.Evidence{{Identity: f.Items[0], Local: local, Health: health, ValidUntil: 2100, RemoteKnown: true}}}, shadowLiteralClock{})
	c.ObserveAuthorized(f.Items[0])
	c.RefreshOnce(t.Context(), func(context.Context, []shadowcoord.Identity) ([]shadowcoord.Result, *shadowcoord.Miss) {
		return []shadowcoord.Result{{Identity: f.Items[0], Grant: f.Grant}}, nil
	})
	return c
}

func TestShadowModuleImportGroups(t *testing.T) {
	for _, path := range []string{"main.go", "http_io.go", "provider_stream.go", "speculation_test.go", "../../internal/shadowcoord/coordinator_test.go"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		start := strings.Index(string(raw), "import (")
		if start < 0 {
			t.Fatal(path)
		}
		block := strings.SplitN(string(raw)[start+len("import ("):], ")", 2)[0]
		standard, module := false, false
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				standard, module = false, false
				continue
			}
			if strings.Contains(line, "github.com/") || strings.Contains(line, "golang.org/") {
				module = true
			} else {
				standard = true
			}
			if standard && module {
				t.Fatal("module import in standard-library group", path, line)
			}
		}
	}
}
