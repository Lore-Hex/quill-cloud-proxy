package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/abuse"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestRequestEndLogsExplicitAbuseOutcomes(t *testing.T) {
	for _, outcome := range []string{abuse.OutcomeCachedReject, abuse.OutcomeRateLimited} {
		t.Run(outcome, func(t *testing.T) {
			var logLine bytes.Buffer
			writeRequestEndLog(
				&logLine, "rlog-test", "POST", "/v1/responses",
				http.StatusUnauthorized, 2, 2, time.Millisecond,
				requestAuditIdentity{}, outcome,
			)
			if !strings.Contains(logLine.String(), `outcome="`+outcome+`"`) {
				t.Fatalf("missing outcome %q: %s", outcome, logLine.String())
			}
		})
	}
}

func TestRequestContractRejectionLogIsMetadataOnlyAndBounded(t *testing.T) {
	var logLine bytes.Buffer
	parameter := strings.Repeat("future_option", 30)
	writeRequestContractRejection(
		&logLine,
		"rlog-contract",
		"/v1/chat/completions",
		http.StatusBadRequest,
		parameter,
	)
	logged := logLine.String()
	for _, want := range []string{
		`enclave.request_contract_rejected`,
		`request_log_id="rlog-contract"`,
		`route="/v1/chat/completions"`,
		`status=400`,
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("contract log missing %q: %s", want, logged)
		}
	}
	if strings.Contains(logged, parameter) || len(logged) > 320 {
		t.Fatalf("contract log was not bounded: %s", logged)
	}
}

func TestRequestAuditResolvesWorkspaceForPreAuthorizationError(t *testing.T) {
	const bearer = "synthetic-private-bearer-material"
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read validation body: %v", err)
		}
		if bytes.Contains(body, []byte(bearer)) {
			t.Fatalf("raw bearer reached control plane: %s", body)
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode validation body: %v", err)
		}
		_, _ = io.WriteString(w, `{"data":{"workspace_id":"ws-customer","api_key_hash":"stored-key-digest"}}`)
	}))
	defer server.Close()

	identity := requestAuditIdentity{}
	identity.bindBearer(bearer)
	identity.resolveFailure(
		t.Context(),
		trustedrouter.New(server.URL, "internal", server.Client()),
		bearer,
		"/v1/responses",
		http.StatusNotImplemented,
	)

	if identity.workspaceID != "ws-customer" || identity.credentialID != "stored-key-digest" {
		t.Fatalf("identity = %#v", identity)
	}
	if identity.attribution != "validation" {
		t.Fatalf("attribution = %q", identity.attribution)
	}
	if got := payload["api_key_lookup_hash"]; got != trustedrouter.LookupHash(bearer) {
		t.Fatalf("lookup hash = %#v", got)
	}
	if got := payload["route_type"]; got != "/v1/responses" {
		t.Fatalf("route type = %#v", got)
	}

	var logLine bytes.Buffer
	writeRequestEndLog(
		&logLine,
		"req-log-1",
		"POST",
		"/v1/responses",
		http.StatusNotImplemented,
		100,
		80,
		12*time.Millisecond,
		identity,
		"",
	)
	logged := logLine.String()
	for _, want := range []string{
		`workspace_id="ws-customer"`,
		`credential_id="stored-key-digest"`,
		`credential_fingerprint="` + trustedrouter.LookupHash(bearer) + `"`,
		`attribution="validation"`,
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("request end log missing %q: %s", want, logged)
		}
	}
	if strings.Contains(logged, bearer) {
		t.Fatalf("request end log leaked bearer: %s", logged)
	}
}

func TestRequestAuditDoesNotValidateSuccessfulRequest(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = io.WriteString(w, `{"data":{"workspace_id":"unexpected","api_key_hash":"unexpected"}}`)
	}))
	defer server.Close()

	identity := requestAuditIdentity{}
	identity.bindBearer("sk-tr-v1-success")
	identity.resolveFailure(
		t.Context(),
		trustedrouter.New(server.URL, "internal", server.Client()),
		"sk-tr-v1-success",
		"/v1/chat/completions",
		http.StatusOK,
	)
	if calls != 0 {
		t.Fatalf("successful request triggered %d identity lookups", calls)
	}
	if identity.workspaceID != "" || identity.attribution != "fingerprint_only" {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestRequestAuditAuthorizationAvoidsFailureLookup(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	identity := requestAuditIdentity{}
	identity.bindBearer("sk-tr-v1-authorized")
	identity.bindAuthorization(&trustedrouter.Authorization{
		WorkspaceID: "ws-authorized",
		APIKeyHash:  "stored-key-authorized",
	})
	identity.resolveFailure(
		t.Context(),
		trustedrouter.New(server.URL, "internal", server.Client()),
		"sk-tr-v1-authorized",
		"/v1/chat/completions",
		http.StatusBadGateway,
	)
	if calls != 0 {
		t.Fatalf("authorized failure triggered %d redundant identity lookups", calls)
	}
	if identity.workspaceID != "ws-authorized" || identity.attribution != "authorization" {
		t.Fatalf("identity = %#v", identity)
	}
}
