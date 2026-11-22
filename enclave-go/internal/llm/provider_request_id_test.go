package llm

import (
	"net/http"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestProviderRequestIDReadsOnlyTheRequestIDHeader(t *testing.T) {
	header := http.Header{}
	header.Set("Authorization", "Bearer secret")
	if got := providerRequestID(header); got != "" {
		t.Fatalf("providerRequestID = %q without a request ID header", got)
	}
	header.Set("Request-Id", "req-b")
	header.Set("X-Request-Id", "req-a")
	if got := providerRequestID(header); got != "req-a" {
		t.Fatalf("providerRequestID = %q, want X-Request-Id first", got)
	}
}

func TestUpstreamHTTPErrorCarriesProviderRequestID(t *testing.T) {
	err := &upstreamHTTPError{status: 400, body: `{"error":{"code":"unsupported_parameter"}}`, requestID: "req_0123abcd"}
	if got := upstreamerror.RequestID(err); got != "req_0123abcd" {
		t.Fatalf("RequestID = %q", got)
	}
}
