package llm

import (
	"net/http"
	"net/url"
	"strings"
)

// ProviderArtifactHTTPClient separates credential-free result downloads from
// inference. Signed CDN URLs cannot be added to the inference allowlist at
// runtime. Requests to approved API hosts retain their normal provider client.
func ProviderArtifactHTTPClient(client *http.Client, rawURL string) (*http.Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" ||
		u.Hostname() == "" || u.Port() != "" {
		return nil, errProviderEgress
	}
	if approvedProviderURL(u) {
		return client, nil
	}
	if _, guarded := client.Transport.(*providerEgressTransport); !guarded {
		// Explicitly injected test/adapter transports keep their own policy.
		return client, nil
	}
	return newProviderArtifactHTTPClient(client, u)
}

type artifactReadOnlyTransport struct {
	base http.RoundTripper
	host string
}

func (t *artifactReadOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	allowed := req.URL != nil && req.URL.Scheme == "https" && req.URL.User == nil &&
		req.URL.Host == t.host && (req.Host == "" || req.Host == t.host) &&
		req.Method == http.MethodGet && (req.Body == nil || req.Body == http.NoBody) &&
		req.ContentLength <= 0
	for name := range req.Header {
		switch strings.ToLower(name) {
		case "accept", "user-agent", "range":
		default:
			allowed = false
		}
	}
	if !allowed {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errProviderEgress
	}
	return t.base.RoundTrip(req)
}

func (t *artifactReadOnlyTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
