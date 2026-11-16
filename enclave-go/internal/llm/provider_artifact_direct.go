//go:build !cloud_aws

package llm

import (
	"net/http"
	"net/url"
	"time"
)

func newProviderArtifactHTTPClient(_ *http.Client, endpoint *url.URL) (*http.Client, error) {
	client, err := NewGuardedHTTPClient("https://"+endpoint.Host, EgressGuardOptions{
		ResponseHeaderTimeout: 30 * time.Second,
		IdleTimeout:           30 * time.Second,
		TotalTimeout:          10 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	client.Transport = &artifactReadOnlyTransport{base: client.Transport, host: endpoint.Host}
	return client, nil
}
