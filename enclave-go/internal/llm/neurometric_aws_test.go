//go:build cloud_aws && llm_multi

package llm

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/vsockhttp"
)

func TestAWSNeurometricLegacyRouteHasMeasuredTunnel(t *testing.T) {
	t.Parallel()

	// Exercise the legacy bootstrap/dispatch path, not directproviders.All().
	var boot qtypes.BootstrapData
	if err := json.Unmarshal([]byte(`{"neurometric_api_key":"test-neurometric-key"}`), &boot); err != nil {
		t.Fatal(err)
	}
	client := New(&boot).(*multiClient).neurometric
	if client == nil || client.apiKey != "test-neurometric-key" {
		t.Fatal("AWS bootstrap key did not reach the Neurometric client")
	}
	endpoint, err := url.Parse(client.baseURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
		t.Fatalf("invalid Neurometric endpoint: %q", client.baseURL)
	}
	for _, provider := range []string{"neurometric", "neurometric-ai"} {
		if directBaseURL(normalizeDirectProvider(provider)) != client.baseURL {
			t.Fatalf("%s does not resolve to the legacy client's endpoint", provider)
		}
	}

	matches := 0
	for _, tunnel := range AWSProviderTunnels() {
		if tunnel.Host != endpoint.Hostname() {
			continue
		}
		matches++
		if tunnel.CID != 3 || tunnel.Port != 8090 {
			t.Fatalf("Neurometric tunnel = %+v, want parent CID 3 port 8090", tunnel)
		}
	}
	if matches != 1 {
		t.Fatalf("legacy Neurometric endpoint %s has %d AWS tunnels, want exactly one", endpoint.Hostname(), matches)
	}

	// The production client must still fail closed, not fall back to direct TCP.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://unconfigured.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.httpc.Do(req)
	if response != nil {
		_ = response.Body.Close()
	}
	var unconfigured *vsockhttp.UnconfiguredHostError
	if !errors.As(err, &unconfigured) || unconfigured.Host != "unconfigured.invalid" {
		t.Fatalf("client did not enforce the AWS hostname allowlist: %v", err)
	}
}
