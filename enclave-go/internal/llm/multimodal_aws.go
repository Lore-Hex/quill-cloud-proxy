//go:build cloud_aws

// AWS Nitro variant of the URL-image fetch.
//
// Nitro Enclaves have NO network stack. Outbound HTTP for arbitrary
// user-supplied image URLs can't be done locally — the parent's
// vsock-proxy daemon only knows about a small allowlist of upstream
// LLM provider hosts (api.anthropic.com, api.openai.com, etc.) plus
// the TR control-plane tunnel on port 8040.
//
// So image-URL fetches travel: enclave → vsock(8040) →
// trustedrouter.com (the TR control plane), which does DNS + SSRF
// rejection + HTTP fetch + size cap server-side and returns
// base64+media_type. The TR side replicates the same IP-class
// rejection rules as multimodal_direct.go's safeImageDialContext.
//
// Trust property: the URL is in the metadata layer (parent's
// vsock-proxy never sees prompt content; the URL is metadata about
// what content the user wants the model to see, not the response
// itself). The image bytes pass through TR → enclave over the
// existing TLS-passthrough vsock tunnel, then the enclave normalizes
// and base64-embeds them into the upstream provider request.
//
// We use a sync.Once-cached trustedrouter.NewFromEnv() rather than
// passing trustedrouter.Client through the call graph because
// (a) llm package doesn't import trustedrouter on the fetch path
// today and (b) image fetches are infrequent — the cache amortizes
// the http.Client setup without coupling.

package llm

import (
	"context"
	"fmt"
	"sync"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

var (
	imageFetchClientOnce sync.Once
	imageFetchClient     *trustedrouter.Client
)

func imageFetchTrustedRouter() *trustedrouter.Client {
	imageFetchClientOnce.Do(func() {
		imageFetchClient = trustedrouter.NewFromEnv()
	})
	return imageFetchClient
}

func fetchHTTPImage(ctx context.Context, rawURL string) (string, []byte, error) {
	tr := imageFetchTrustedRouter()
	if tr == nil || !tr.Enabled() {
		// Match the message used by multimodal_direct.go on resolve
		// failure so callers see consistent errors. The enclave is
		// truly unable to reach this URL — TR isn't configured.
		return "", nil, fmt.Errorf("llm/image: fetch failed")
	}
	mediaType, data, err := tr.FetchImage(ctx, rawURL)
	if err != nil {
		// Surface the TR-control-plane error via the same wrapper
		// other llm/image paths use. The TR side returns the
		// IP-class rejection (private/loopback) as an HTTP 400 with
		// "private address" in the message; bubble that up so the
		// downstream provider call doesn't blindly retry.
		return "", nil, fmt.Errorf("llm/image: %w", err)
	}
	return mediaType, data, nil
}
