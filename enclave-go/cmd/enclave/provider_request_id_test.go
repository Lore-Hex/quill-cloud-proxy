package main

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// providerFailureWithRequestID is a provider 4xx that carries the provider's
// own request ID, as llm's upstream HTTP error does.
type providerFailureWithRequestID struct {
	status int
	body   string
	id     string
}

func (e *providerFailureWithRequestID) Error() string { return "llm/upstream: provider error" }
func (e *providerFailureWithRequestID) UpstreamResponse() (int, string) {
	return e.status, e.body
}
func (e *providerFailureWithRequestID) UpstreamRequestID() string { return e.id }

const unsupportedParameterBody = `{"error":{"message":"That request was rejected.","type":"invalid_request_error","code":"unsupported_parameter","param":"temperature"}}`

func TestProviderErrorBodyForwardsCodeTypeParamAndProviderRequestID(t *testing.T) {
	err := fmt.Errorf("llm/boundless: %w", &providerFailureWithRequestID{400, unsupportedParameterBody, "req_0123abcd"})
	status, body := providerErrorBody(err, &trustedrouter.Authorization{})
	if status != 400 {
		t.Fatalf("status = %d", status)
	}
	if body["type"] != "invalid_request_error" || body["code"] != "unsupported_parameter" || body["param"] != "temperature" {
		t.Fatalf("type/code/param not forwarded: %#v", body)
	}
	metadata, _ := body["metadata"].(map[string]any)
	if metadata["provider_request_id"] != "req_0123abcd" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if _, err := json.Marshal(body); err != nil {
		t.Fatal(err)
	}
}

func TestProviderErrorBodyOmitsProviderRequestIDWhenHiddenOrUnsafe(t *testing.T) {
	hidden := fmt.Errorf("llm/boundless: %w", &providerFailureWithRequestID{400, unsupportedParameterBody, "req_0123abcd"})
	_, body := providerErrorBody(hidden, &trustedrouter.Authorization{HidePublicMetadata: true})
	if _, ok := body["metadata"]; ok {
		t.Fatalf("hidden route carries metadata: %#v", body)
	}

	unsafe := fmt.Errorf("llm/boundless: %w", &providerFailureWithRequestID{400, unsupportedParameterBody, "id\r\nX-Injected: 1"})
	_, body = providerErrorBody(unsafe, &trustedrouter.Authorization{})
	metadata, _ := body["metadata"].(map[string]any)
	if _, ok := metadata["provider_request_id"]; ok {
		t.Fatalf("unsafe request ID forwarded: %#v", metadata)
	}

	// No request ID and no structured body: the response is unchanged.
	plain := fmt.Errorf("llm/boundless: %w", &providerFailureWithRequestID{400, "", ""})
	_, body = providerErrorBody(plain, &trustedrouter.Authorization{})
	if _, ok := body["metadata"]; ok {
		t.Fatalf("empty failure grew metadata: %#v", body)
	}
}
