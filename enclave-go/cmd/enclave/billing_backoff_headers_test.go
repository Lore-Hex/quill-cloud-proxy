package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func billingHeaderGateway(t *testing.T) (*trustedrouter.Client, *int) {
	t.Helper()
	t.Setenv("QUILL_BILLING_402_BACKOFF_MS", "5000")
	calls := new(int)
	gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: astraTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/internal/gateway/authorize" {
			*calls++
			return astraResponse(402, `{"error":{"type":"insufficient_credits","message":"top up"}}`), nil
		}
		return astraResponse(200, `{"data":{"workspace_id":"ws","api_key_hash":"credential"}}`), nil
	})})
	return gateway, calls
}

// Each validation/authorization header must miss on a different value, then silently reuse
// its own window. Counters prove a new 402 is an authorize miss, not a cache hit.
func checkBillingHeaderVariants(t *testing.T, variants ...string) {
	t.Helper()
	gateway, calls := billingHeaderGateway(t)
	for i, headers := range append([]string{""}, variants...) {
		first, _ := astraRequest(t, gateway, "/v1/chat/completions", astraChat, headers)
		if parseHTTPStatus(first) != 402 || *calls != i+1 {
			t.Fatalf("header variant %d did not miss: authorize calls=%d want=%d response=%s", i, *calls, i+1, first)
		}
		again, logs := astraRequest(t, gateway, "/v1/chat/completions", astraChat, headers)
		if *calls != i+1 || !bytes.Equal(first, again) || logs != "" {
			t.Fatalf("identical header storm did not hit silently: calls=%d logs=%q", *calls, logs)
		}
	}
}

func checkBillingHeaderInvalid(t *testing.T, headers string) {
	t.Helper()
	gateway, calls := billingHeaderGateway(t)
	cold, _ := astraRequest(t, gateway, "/v1/chat/completions", astraChat, headers)
	seed, _ := astraRequest(t, gateway, "/v1/chat/completions", astraChat, "")
	warm, _ := astraRequest(t, gateway, "/v1/chat/completions", astraChat, headers)
	if parseHTTPStatus(cold) != 400 || parseHTTPStatus(seed) != 402 || parseHTTPStatus(warm) != 400 || *calls != 1 {
		t.Fatalf("ordinary header 400 masked: cold=%s seed=%s warm=%s authorize calls=%d", cold, seed, warm, *calls)
	}
}

func TestBillingHeaderAttribution(t *testing.T) {
	t.Setenv("TR_REQUEST_METADATA_ENFORCEMENT", "enforce")
	for _, tc := range []struct{ name, first, second, invalid string }{
		{"HTTP-Referer", "https://one.example", "https://two.example", "not-a-url"},
		{"X-Title", "one", "two", strings.Repeat("x", 121)},
		{"X-OpenRouter-Title", "one", "two", strings.Repeat("x", 121)},
		{"X-OpenRouter-Categories", "coding", "writing", "INVALID!"},
		{"X-Session-ID", "one", "two", strings.Repeat("x", 257)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkBillingHeaderVariants(t, tc.name+": "+tc.first+"\r\n", tc.name+": "+tc.second+"\r\n")
			checkBillingHeaderInvalid(t, tc.name+": "+tc.invalid+"\r\n")
		})
	}
	for _, name := range []string{"X-OpenRouter-Metadata", "X-OpenRouter-Experimental-Metadata"} {
		t.Run(name, func(t *testing.T) {
			checkBillingHeaderVariants(t, name+": enabled\r\n")
			// Non-enabled values are intentionally false, not semantic errors.
			checkBillingHeaderInvalid(t, name+": bad\x01value\r\n")
		})
	}
}

// Include every captured telemetry field, plus values dropped by the parser.
var billingTelemetryHeaders = []struct{ name, first, second string }{
	{"User-Agent", "trusted-router-py/1.2.3", "trusted-router-go/1.2.3"},
	{"X-TR-Client", "v=1;a=1", "v=1;a=2"},
	{"X-Stainless-Lang", "python", "go"},
	{"X-Stainless-Runtime", "python", "node"},
	{"X-Stainless-Runtime-Version", "3.12.0", "3.13.0"},
	{"X-Stainless-OS", "linux", "windows"},
	{"X-Stainless-Arch", "x64", "arm64"},
	{"X-Stainless-Retry-Count", "1", "2"},
	{"X-Stainless-Timeout", "1", "2"},
	{"X-Stainless-Read-Timeout", "1", "2"},
}

var billingDroppedTelemetryHeaders = []string{
	"X-TR-Client: malformed\r\n", "X-Stainless-Retry-Count: nope\r\n",
	"X-Stainless-Timeout: NaN\r\n", "X-Stainless-Read-Timeout: NaN\r\n",
	"User-Agent: " + strings.Repeat("x", 257) + "\r\n",
	"X-Stainless-OS: " + strings.Repeat("x", 65) + "\r\n",
	"X-TR-Client: " + strings.Repeat("x", 161) + "\r\n",
}

func TestBillingHeaderClientContext(t *testing.T) {
	for _, tc := range billingTelemetryHeaders {
		t.Run(tc.name, func(t *testing.T) {
			gateway, calls := billingHeaderGateway(t)
			first, _ := astraRequest(t, gateway, "/v1/chat/completions", astraChat, "")
			for _, value := range []string{tc.first, tc.second, ""} {
				response, logs := astraRequest(t, gateway, "/v1/chat/completions", astraChat, tc.name+": "+value+"\r\n")
				if parseHTTPStatus(first) != 402 || !bytes.Equal(first, response) || *calls != 1 || logs != "" {
					t.Fatalf("telemetry split billing window: calls=%d response=%s logs=%q", *calls, response, logs)
				}
			}
			// HTTP syntax errors still reject before lookup.
			checkBillingHeaderInvalid(t, tc.name+": bad\x01value\r\n")
		})
	}
	for _, headers := range billingDroppedTelemetryHeaders {
		t.Run(headers[:strings.IndexByte(headers, ':')]+" dropped", func(t *testing.T) {
			for _, seed := range []string{"", headers} {
				gateway, calls := billingHeaderGateway(t)
				first, logs := astraRequest(t, gateway, "/v1/chat/completions", astraChat, seed)
				if parseHTTPStatus(first) != 402 || *calls != 1 || (seed != "" && !strings.Contains(logs, "enclave.client_context_dropped")) {
					t.Fatalf("miss lost drop-and-diagnose behavior: calls=%d response=%s logs=%s", *calls, first, logs)
				}
				for _, hit := range []string{headers, "", "User-Agent: trusted-router-py/1.2.3\r\n"} {
					response, logs := astraRequest(t, gateway, "/v1/chat/completions", astraChat, hit)
					if !bytes.Equal(first, response) || *calls != 1 || logs != "" {
						t.Fatalf("dropped telemetry did not hit silently: calls=%d response=%s logs=%s", *calls, response, logs)
					}
				}
			}
		})
	}
}

// Telemetry may be excluded from the key only while it cannot change authorize
// or reject inference. Disable backoff so cache hits cannot hide such a change.
// Compare the actual wire payload, excluding only generated invocation IDs.
func TestBillingTelemetryAuthorizeEquivalence(t *testing.T) {
	t.Setenv("QUILL_BILLING_402_BACKOFF_MS", "0")
	t.Setenv("TR_REQUEST_METADATA_ENFORCEMENT", "enforce")
	headers := []string{""}
	for _, tc := range billingTelemetryHeaders {
		for _, value := range []string{tc.first, tc.second, "", strings.Repeat("x", 257)} {
			headers = append(headers, tc.name+": "+value+"\r\n")
		}
	}
	headers = append(headers, billingDroppedTelemetryHeaders...)
	for route, body := range map[string]string{
		"/v1/chat/completions": astraChat,
		"/v1/responses":        `{"model":"test-model","input":"hi"}`,
		"/v1/messages":         `{"model":"test-model","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`,
		"/v1/embeddings":       `{"model":"test-model","input":"hi"}`,
		"/v1/images":           `{"model":"google/gemini-3.1-flash-image","prompt":"cat"}`,
		"/api/alpha/decide":    decideBody,
	} {
		t.Run(route, func(t *testing.T) {
			var baseline, captured map[string]any
			calls := 0
			gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: astraTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/internal/gateway/authorize" {
					calls++
					if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
						t.Fatal(err)
					}
					return astraResponse(402, `{"error":{"type":"insufficient_credits","message":"top up"}}`), nil
				}
				return astraResponse(200, `{"data":{"workspace_id":"ws","api_key_hash":"credential"}}`), nil
			})})
			for i, telemetry := range headers {
				captured = nil
				response, _ := astraRequest(t, gateway, route, body, telemetry)
				if parseHTTPStatus(response) != 402 || calls != i+1 || captured == nil {
					t.Fatalf("telemetry rejected or skipped authorize: headers=%q calls=%d response=%s", telemetry, calls, response)
				}
				for _, field := range []string{"idempotency_key", "invocation_nonce"} {
					if value, ok := captured[field].(string); !ok || value == "" {
						t.Fatalf("missing generated %s: %v", field, captured)
					}
					delete(captured, field)
				}
				if i == 0 {
					baseline = captured
				} else if !reflect.DeepEqual(baseline, captured) {
					t.Fatalf("telemetry changed authorize while excluded from key: headers=%q\nwithout=%v\nwith=%v", telemetry, baseline, captured)
				}
			}
		})
	}
}

func TestBillingHeaderReceipt(t *testing.T) {
	resetReceiptTestState(t)
	var err error
	receiptSigner, err = receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	checkBillingHeaderVariants(t, "X-Inference-Receipt: true\r\n", "X-Inference-Receipt: nonce-one\r\n", "X-Inference-Receipt: nonce-two\r\n")
	checkBillingHeaderInvalid(t, "X-Inference-Receipt: not a nonce\r\n")
}

func TestBillingHeaderHost(t *testing.T) {
	checkBillingHeaderVariants(t, "Host: one.example\r\n", "Host: two.example\r\n")
	checkBillingHeaderInvalid(t, "Host: one.example\r\nHost: two.example\r\n")
	gateway := astraGateway(t)
	const route = "/v1/images"
	const body = `{"model":"google/gemini-3.1-flash-image","prompt":"cat"}`
	const headers = "Host: api.confidential.trustedrouter.com\r\n"
	cold, _ := astraRequest(t, gateway, route, body, headers)
	seed, _ := astraRequest(t, gateway, route, body, "")
	warm, _ := astraRequest(t, gateway, route, body, headers)
	if parseHTTPStatus(cold) != 400 || parseHTTPStatus(seed) != 402 || parseHTTPStatus(warm) != 400 {
		t.Fatalf("confidential Host validation masked: cold=%s seed=%s warm=%s", cold, seed, warm)
	}
}

func TestBillingHeaderCanonicalEquivalence(t *testing.T) {
	key := func(headers string, confidential bool) trustedrouter.BillingBackoffKey {
		_, _, _, _, a, _, err := readRequest(bufio.NewReader(strings.NewReader(astraRaw("/v1/chat/completions", astraChat, headers))))
		if err != nil {
			t.Fatal(err)
		}
		return trustedrouter.NewBillingBackoffKey(trustedrouter.LookupHash("review-key"), "POST", "/v1/chat/completions", []byte(astraChat), billingBackoffHeaderGroups(a, confidential)...)
	}
	a := key("X-Title: app\r\nX-OpenRouter-Categories: coding, writing\r\n", false)
	b := key("x-openrouter-categories: coding,writing\r\nx-openrouter-title: app\r\n", false)
	if a != b {
		t.Fatal("parsed aliases/order not canonical")
	}
	if key("", false) == key("", true) {
		t.Fatal("TLS confidential mode aliased ordinary mode")
	}
	for _, headers := range []string{"Connection: close\r\n", "Date: yesterday\r\n", "X-Request-ID: random\r\n"} {
		if key(headers, false) != key("", false) {
			t.Fatalf("transport/random header entered key: %q", headers)
		}
	}
	// Different boundaries must never alias, even if concatenated bytes agree.
	if key("X-Title: ab\r\nX-Session-ID: c\r\n", false) == key("X-Title: b\r\nX-Session-ID: ca\r\n", false) {
		t.Fatal("attribution fields were not length framed")
	}
}

func TestBillingHeaderStorm(t *testing.T) {
	t.Setenv("TR_REQUEST_METADATA_ENFORCEMENT", "enforce")
	resetReceiptTestState(t)
	var err error
	receiptSigner, err = receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	const headers = "HTTP-Referer: https://app.example\r\nX-Title: storm\r\nX-Session-ID: session\r\nX-OpenRouter-Categories: coding\r\nX-TR-Client: v=1;a=1\r\nUser-Agent: trusted-router-py/1.2.3\r\nX-Inference-Receipt: storm-nonce\r\n"
	for route, body := range map[string]string{
		"/v1/chat/completions": astraChat,
		"/v1/responses":        `{"model":"test-model","input":"hi"}`,
		"/v1/messages":         `{"model":"test-model","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`,
		"/v1/embeddings":       `{"model":"test-model","input":"hi"}`,
		"/v1/images":           `{"model":"google/gemini-3.1-flash-image","prompt":"cat"}`,
		"/api/alpha/decide":    decideBody,
	} {
		t.Run(route, func(t *testing.T) {
			gateway, calls := billingHeaderGateway(t)
			first, _ := astraRequest(t, gateway, route, body, headers)
			if parseHTTPStatus(first) != 402 || *calls != 1 {
				t.Fatalf("seed: %s calls=%d", first, *calls)
			}
			for i := 0; i < 50; i++ {
				response, logs := astraRequest(t, gateway, route, body, headers)
				if !bytes.Equal(first, response) || logs != "" || *calls != 1 {
					t.Fatalf("storm request %d missed: response=%s calls=%d logs=%q", i, response, *calls, logs)
				}
			}
		})
	}
}
