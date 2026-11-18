package llm

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/directproviders"
)

// This policy is compiled into the measured image. No request, environment
// variable, catalog entry, or bootstrap response can add a destination.
var providerEgressHosts = func() map[string]struct{} {
	hosts := map[string]struct{}{}
	for _, spec := range directproviders.All() {
		// These require their dedicated encrypted transports, not ordinary HTTPS.
		if spec.Provider == "privatemode" || spec.Provider == "maple" {
			continue
		}
		u, err := url.Parse(spec.BaseURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			panic("invalid compiled provider endpoint")
		}
		hosts[u.Hostname()] = struct{}{}
	}
	for _, host := range []string{
		"api.anthropic.com", "api.openai.com", "openrouter.ai",
		"api.cerebras.ai", "api.deepseek.com", "api.mistral.ai", "api.moonshot.ai",
		"generativelanguage.googleapis.com", "api.z.ai", "api.together.xyz",
		"api.fireworks.ai", "api.voyageai.com", "api.xiaomimimo.com", "api.x.ai",
		"api.novita.ai", "api.redpill.ai", "api.siliconflow.com", "inference.tinfoil.sh",
		"api.venice.ai", "api.parasail.io", "lightning.ai", "api.gmi-serving.com",
		"api.deepinfra.com", "api.friendli.ai", "inference.baseten.co", "api.telnyx.com",
		"tinker.thinkingmachines.dev", "pass.wafer.ai", "api.inference.crusoecloud.com",
		"inference.makora.com", "api.tokenfactory.nebius.com", "api.minimax.io",
		"inference.do-ai.run", "api.inceptron.io", "api.morphllm.com", "api.atlascloud.ai",
		"vanchin.streamlake.ai", "wharf.neurometric.ai", "inference.pearlresearch.ai",
		"api.engy.ai", "api.stepfun.ai", "models.relace.ai", "router-api.0g.ai",
		"ws-el6e4bpnggpx7g88.eu-central-1.maas.aliyuncs.com", // gitleaks:allow public Alibaba workspace hostname
		"trustedrouter-foundry-eastus2.openai.azure.com",
		"trustedrouter-foundry-eastus2.services.ai.azure.com",
		"dbc-7ccfd8c0-c0da.cloud.databricks.com",
		"api.cloudflare.com", "api.cohere.com", "api.chutes.ai", "llm.chutes.ai",
		"bedrock-runtime.us-east-1.amazonaws.com", "bedrock.us-east-1.amazonaws.com",
		"bedrock.us-east-2.amazonaws.com", "bedrock.us-west-2.amazonaws.com",
		"aiplatform.googleapis.com", "aiplatform.us.rep.googleapis.com", "aiplatform.eu.rep.googleapis.com",
		"us-central1-aiplatform.googleapis.com", "us-east1-aiplatform.googleapis.com",
		"us-east4-aiplatform.googleapis.com", "us-west1-aiplatform.googleapis.com",
		"europe-west4-aiplatform.googleapis.com",
		"external.api.recraft.ai", "api.bfl.ai", "api.us.bfl.ai", "api.eu.bfl.ai",
		"api.us1.bfl.ai", "api.eu1.bfl.ai", "api.eu2.bfl.ai",
		"api.decart.ai", "api.ltx.io", "api.dev.runwayml.com", "api-singapore.klingai.com",
		"queue.fal.run", "eastus2.tts.speech.microsoft.com", "api.exa.ai", "api.context.dev",
		"ark-acg-ap-southeast-1.tos-ap-southeast-1.volces.com", // gitleaks:allow public BytePlus object-storage hostname
	} {
		hosts[host] = struct{}{}
	}
	return hosts
}()

var errProviderEgress = errors.New("provider egress: destination is not approved")

// IsProviderEgressDenied lets asynchronous adapters distinguish a permanent
// policy rejection from a transient provider/network error when polling.
func IsProviderEgressDenied(err error) bool { return errors.Is(err, errProviderEgress) }

// providerEgressHostPatterns admit the customer-chosen hosts of native
// cloud BYOK credentials (Amazon Bedrock, Google Vertex, Azure). They are
// compiled into the measured image like the exact list above and name only
// provider-operated domains: an AWS region's Bedrock endpoints, a Vertex
// location, and an Azure OpenAI / AI Foundry resource. No request, credential
// or catalog entry can widen them, and every dial still requires public IPs.
var providerEgressHostPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^bedrock-runtime\.[a-z]{2}(-gov)?-[a-z]+-[0-9]\.amazonaws\.com$`),
	regexp.MustCompile(`^bedrock-mantle\.[a-z]{2}(-gov)?-[a-z]+-[0-9]\.api\.aws$`),
	regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+-aiplatform\.googleapis\.com$`),
	regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}\.(openai\.azure\.com|services\.ai\.azure\.com|cognitiveservices\.azure\.com)$`),
}

// googleOAuthHost is where a BYOK service account's signed assertion is
// exchanged for an access token. Nothing else is sent there.
const googleOAuthHost = "oauth2.googleapis.com"

func approvedProviderHost(host string) bool {
	host = strings.ToLower(host)
	if _, ok := providerEgressHosts[host]; ok || host == googleOAuthHost {
		return true
	}
	for _, pattern := range providerEgressHostPatterns {
		if pattern.MatchString(host) {
			return true
		}
	}
	return false
}

func approvedProviderURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.User == nil && u.Opaque == "" &&
		u.Fragment == "" && (u.Port() == "" || u.Port() == "443") &&
		approvedProviderHost(u.Hostname()) &&
		(strings.EqualFold(u.Host, u.Hostname()) || strings.EqualFold(u.Host, u.Hostname()+":443"))
}

const providerMetadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- URL, not a credential.

// Vertex's existing token bootstrap is the sole HTTP exception, restricted to
// an exact read-only path. It cannot carry inference bodies or credentials.
func approvedMetadataRequest(req *http.Request) bool {
	return req.URL.String() == providerMetadataTokenURL && req.Method == http.MethodGet &&
		(req.Body == nil || req.Body == http.NoBody) && req.ContentLength <= 0 &&
		len(req.Header.Values("Metadata-Flavor")) == 1 && req.Header.Get("Metadata-Flavor") == "Google" &&
		len(req.Header) == 1
}

type providerEgressTransport struct{ base http.RoundTripper }

func (t *providerEgressTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check every request, including reused connections and clients whose caller
	// replaces CheckRedirect. Never log a URL, query, body, or credential here.
	if req == nil || req.URL == nil || req.Response != nil ||
		(req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host)) ||
		(!approvedProviderURL(req.URL) && !approvedMetadataRequest(req)) {
		if req != nil && req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errProviderEgress
	}
	return t.base.RoundTrip(req)
}

func (t *providerEgressTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type pinnedProviderEgressTransport struct {
	base http.RoundTripper
	host string
}

func approvedPinnedProviderRequest(req *http.Request, host string) bool {
	return req != nil && req.URL != nil && req.Response == nil &&
		req.URL.Scheme == "https" && req.URL.User == nil && req.URL.Opaque == "" &&
		req.URL.Fragment == "" && strings.EqualFold(req.URL.Hostname(), host) &&
		(strings.EqualFold(req.URL.Host, host) || strings.EqualFold(req.URL.Host, host+":443")) &&
		(req.Host == "" || strings.EqualFold(req.Host, req.URL.Host))
}

func (t *pinnedProviderEgressTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !approvedPinnedProviderRequest(req, t.host) {
		if req != nil && req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errProviderEgress
	}
	return t.base.RoundTrip(req)
}

func (t *pinnedProviderEgressTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func lockProviderHTTPClient(client *http.Client) *http.Client {
	client.Transport = &providerEgressTransport{base: client.Transport}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

// The dial check complements the per-request check and pins vetted DNS results
// for this connection. TLS still verifies the original hostname and receipt
// collection still observes the actual serving certificate.
func providerDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return providerDialWith(ctx, network, address, net.DefaultResolver, dialer.DialContext)
}

func providerDialWith(ctx context.Context, network, address string, resolver IPResolver,
	dial func(context.Context, string, string) (net.Conn, error),
) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || (network != "tcp" && network != "tcp4" && network != "tcp6") {
		return nil, errProviderEgress
	}
	if host == "metadata.google.internal" && port == "80" {
		return dial(ctx, network, address)
	}
	if port != "443" || !approvedProviderHost(host) {
		return nil, errProviderEgress
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("provider egress: DNS lookup failed")
	}
	for _, ip := range ips {
		if !allowedPublicIP(ip.Unmap()) {
			return nil, errProviderEgress
		}
	}
	// Keep a blackholed address from consuming the entire connection budget
	// before another already-vetted address can be tried.
	perAddress := max(2*time.Second, 10*time.Second/time.Duration(len(ips)))
	for _, ip := range ips {
		dialCtx, cancelDial := context.WithTimeout(ctx, perAddress)
		conn, dialErr := dial(dialCtx, network, net.JoinHostPort(ip.Unmap().String(), port))
		cancelDial()
		if dialErr == nil {
			return conn, nil
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, errors.New("provider egress: approved endpoint unavailable")
}
