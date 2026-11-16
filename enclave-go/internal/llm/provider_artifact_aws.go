//go:build cloud_aws

package llm

import (
	"net/http"
	"net/url"
)

func newProviderArtifactHTTPClient(_ *http.Client, _ *url.URL) (*http.Client, error) {
	// Nitro has no public network; do not add arbitrary CDN tunnels.
	return nil, errProviderEgress
}
