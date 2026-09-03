package trustedrouter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func stageDFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", "stage_d", name)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type stageDWireRoundTripFunc func(*http.Request) (*http.Response, error)

func (f stageDWireRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func stageDTestClient(t *testing.T, transport stageDWireRoundTripFunc) (*Client, *receipt.Signer) {
	t.Helper()
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: transport})
	client.ConfigureStageDBoot(signer)
	return client, signer
}

func stageDParseBootAuthHeader(t *testing.T, value string) (string, []byte) {
	t.Helper()
	kidPart, signaturePart, ok := strings.Cut(value, ",")
	if !ok || !strings.HasPrefix(kidPart, "kid=") || !strings.HasPrefix(signaturePart, "sig=") {
		t.Fatalf("X-TR-Boot-Auth = %q", value)
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(signaturePart, "sig="))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(kidPart, "kid="), signature
}

func TestStageDAuthorizeResponseParsesPinnedBytes(t *testing.T) {
	for _, test := range []struct {
		name     string
		eligible bool
		reason   string
	}{
		{"authorize_response_eligible.json", true, "ok"},
		{"authorize_response_ineligible.json", false, "not_streaming"},
	} {
		var envelope struct {
			Data Authorization `json:"data"`
		}
		if err := json.Unmarshal(stageDFixture(t, test.name), &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Data.StageD.Eligible != test.eligible || envelope.Data.StageD.Reason != test.reason {
			t.Fatalf("%s stage_d = %#v", test.name, envelope.Data.StageD)
		}
		if test.eligible {
			if envelope.Data.CapMicro != 300 || len(envelope.Data.CandidatePrices) != 1 {
				t.Fatalf("eligible pricing = %#v cap=%d", envelope.Data.CandidatePrices, envelope.Data.CapMicro)
			}
			rates := envelope.Data.CandidatePrices[0].RatesForPrompt(200001)
			if rates.OutputMicroPerMillion != 3000000 {
				t.Fatalf("tier output rate = %d", rates.OutputMicroPerMillion)
			}
		}
	}
}

func TestStageDPinnedPricingDocumentParsesAllIntegerRates(t *testing.T) {
	var document struct {
		Version    int              `json:"v"`
		Kind       string           `json:"kind"`
		Candidates []CandidatePrice `json:"candidates"`
	}
	if err := json.Unmarshal(stageDFixture(t, "pricing_document.json"), &document); err != nil {
		t.Fatal(err)
	}
	if document.Version != 1 || document.Kind != "endpoint" || len(document.Candidates) != 1 {
		t.Fatalf("document=%#v", document)
	}
	if got := document.Candidates[0].RatesForPrompt(200_001).CacheCreationMicroPerMillion; got != 2_500_000 {
		t.Fatalf("tier cache-creation rate=%d", got)
	}
}

func TestAuthorizeCarriesRequestStreamAndParsesStageD(t *testing.T) {
	for _, stream := range []bool{false, true} {
		client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: stageDWireRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get(spendlease.BootAuthHeader) == "" {
				t.Fatal("Stage D authorize was not boot signed")
			}
			body, _ := io.ReadAll(req.Body)
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			if got, ok := payload["stream"].(bool); !ok || got != stream {
				t.Fatalf("stream=%v present=%t want=%t body=%s", got, ok, stream, body)
			}
			fixture := "authorize_response_ineligible.json"
			if stream {
				fixture = "authorize_response_eligible.json"
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(stageDFixture(t, fixture))), Request: req}, nil
		})})
		signer, err := receipt.NewSigner()
		if err != nil {
			t.Fatal(err)
		}
		client.ConfigureStageDBoot(signer)
		auth, err := client.AuthorizeWithRoute(context.Background(), "sk-test", &qtypes.OpenAIChatRequest{Model: "model", Stream: stream}, "chat.completions")
		if err != nil || auth.StageD.Eligible != stream {
			t.Fatalf("auth=%#v err=%v", auth, err)
		}
	}
}

func TestHeartbeatUsesPinnedRequestBytesAndBootSignature(t *testing.T) {
	wantBody := stageDFixture(t, "heartbeat_request.json")
	wantResponse := stageDFixture(t, "heartbeat_response_accepted.json")
	var request HeartbeatRequest
	if err := json.Unmarshal(wantBody, &request); err != nil {
		t.Fatal(err)
	}
	var wireBody []byte
	var header string
	client, signer := stageDTestClient(t, func(req *http.Request) (*http.Response, error) {
		wireBody, _ = io.ReadAll(req.Body)
		header = req.Header.Get(spendlease.BootAuthHeader)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(wantResponse)), Request: req}, nil
	})
	response, err := client.Heartbeat(context.Background(), &Authorization{AuthorizationID: request.AuthorizationID}, request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wireBody, wantBody) {
		t.Fatalf("heartbeat wire bytes differ\ngot:  %s\nwant: %s", wireBody, wantBody)
	}
	if response.Seq != 1 || response.RunningMicro != 120 {
		t.Fatalf("heartbeat response = %#v", response)
	}
	kid, signature := stageDParseBootAuthHeader(t, header)
	if kid != signer.Kid() {
		t.Fatalf("kid = %q", kid)
	}
	publicKey, _ := base64.RawURLEncoding.DecodeString(signer.JWK().X)
	digest := spendlease.AuthorizeDigest(http.MethodPost, HeartbeatPath, wantBody)
	if !ed25519.Verify(publicKey, digest[:], signature) {
		t.Fatal("heartbeat signature does not cover pinned bytes")
	}
}

func TestHeartbeatRetryReusesExactDuplicatePinnedBytes(t *testing.T) {
	want := stageDFixture(t, "heartbeat_request_duplicate.json")
	var request HeartbeatRequest
	if err := json.Unmarshal(want, &request); err != nil {
		t.Fatal(err)
	}
	var bodies [][]byte
	var headers []string
	attempt := 0
	client, _ := stageDTestClient(t, func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		bodies = append(bodies, body)
		headers = append(headers, req.Header.Get(spendlease.BootAuthHeader))
		attempt++
		if attempt == 1 {
			return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(`{"error":{"type":"unavailable"}}`)), Request: req}, nil
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(stageDFixture(t, "heartbeat_response_duplicate.json"))), Request: req}, nil
	})
	client.authorizeRetry = retryPolicy{attempts: 2, sleep: func(context.Context, time.Duration) error { return nil }}
	if _, err := client.Heartbeat(context.Background(), &Authorization{AuthorizationID: request.AuthorizationID}, request); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], want) || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("retry bodies are not pinned duplicates: %q", bodies)
	}
	if len(headers) != 2 || headers[0] == "" || headers[0] != headers[1] {
		t.Fatalf("retry signatures differ: %q", headers)
	}
}

func TestHeartbeatPinnedRejectionsAreTyped(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reason HeartbeatRejectionReason
	}{
		{"unknown_authorization", 404, HeartbeatUnknownAuthorization},
		{"already_terminal", 409, HeartbeatAlreadyTerminal},
		{"out_of_cohort", 409, HeartbeatOutOfCohort},
		{"boot_not_accepted", 401, HeartbeatBootNotAccepted},
		{"stale_seq", 409, HeartbeatStaleSeq},
		{"endpoint_mismatch", 409, HeartbeatEndpointMismatch},
		{"usage_regression", 409, HeartbeatUsageRegression},
		{"usage_exceeds_cap", 409, HeartbeatUsageExceedsCap},
	}
	wantRequest := stageDFixture(t, "heartbeat_request.json")
	var request HeartbeatRequest
	if err := json.Unmarshal(wantRequest, &request); err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _ := stageDTestClient(t, func(req *http.Request) (*http.Response, error) {
				wire, _ := io.ReadAll(req.Body)
				if !bytes.Equal(wire, wantRequest) {
					t.Fatalf("request bytes = %s", wire)
				}
				return &http.Response{StatusCode: test.status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(stageDFixture(t, "rejection_"+test.name+".json"))), Request: req}, nil
			})
			_, err := client.Heartbeat(context.Background(), &Authorization{AuthorizationID: request.AuthorizationID}, request)
			if reason, ok := HeartbeatRejection(err); !ok || reason != test.reason {
				t.Fatalf("rejection = %q,%t err=%v", reason, ok, err)
			}
		})
	}
}

func TestStageDDispositionAndSettlementFixturesParseLiterally(t *testing.T) {
	for _, prefix := range []string{"settle", "refund"} {
		for _, disposition := range []string{DispositionFinalized, DispositionIntentDurable, DispositionAlreadyFinalized, DispositionReapedSnapshot} {
			var envelope struct {
				Data SettleResult `json:"data"`
			}
			if err := json.Unmarshal(stageDFixture(t, fmt.Sprintf("%s_response_%s.json", prefix, disposition)), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Data.Disposition != disposition {
				t.Fatalf("%s/%s = %#v", prefix, disposition, envelope.Data)
			}
		}
	}
	var late struct {
		Data SettleResult `json:"data"`
	}
	if err := json.Unmarshal(stageDFixture(t, "late_settle_after_reaped_snapshot_response.json"), &late); err != nil {
		t.Fatal(err)
	}
	if late.Data.Disposition != DispositionReapedSnapshot || !late.Data.AlreadySettled || !late.Data.Settled {
		t.Fatalf("late settle = %#v", late.Data)
	}
	var lookup struct {
		Data DispositionResult `json:"data"`
	}
	if err := json.Unmarshal(stageDFixture(t, "disposition_lookup_response.json"), &lookup); err != nil {
		t.Fatal(err)
	}
	if lookup.Data.Disposition != DispositionReapedSnapshot {
		t.Fatalf("lookup = %#v", lookup.Data)
	}
}

func TestDispositionGETIsBootSigned(t *testing.T) {
	want := stageDFixture(t, "disposition_lookup_response.json")
	var header string
	client, signer := stageDTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/internal/gateway/authorizations/gwa-stage-d-fixture/disposition" {
			t.Fatalf("request = %s %s", req.Method, req.URL.Path)
		}
		header = req.Header.Get(spendlease.BootAuthHeader)
		if header == "" {
			t.Fatal("missing boot auth")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(want)), Request: req}, nil
	})
	result, err := client.Disposition(context.Background(), &Authorization{AuthorizationID: "gwa-stage-d-fixture"})
	if err != nil || result.Disposition != DispositionReapedSnapshot {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	kid, signature := stageDParseBootAuthHeader(t, header)
	if kid != signer.Kid() {
		t.Fatalf("kid=%q", kid)
	}
	publicKey, _ := base64.RawURLEncoding.DecodeString(signer.JWK().X)
	digest := spendlease.AuthorizeDigest(http.MethodGet, "/internal/gateway/authorizations/gwa-stage-d-fixture/disposition", nil)
	if !ed25519.Verify(publicKey, digest[:], signature) {
		t.Fatal("disposition signature does not cover method and path")
	}
}
