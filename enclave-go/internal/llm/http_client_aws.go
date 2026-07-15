//go:build cloud_aws

// defaultHTTPClient — vsock-tunneled variant for AWS-side Nitro
// Enclaves.
//
// Nitro Enclaves have NO network interface. Outbound HTTPS to LLM
// providers (api.anthropic.com etc.) and to GCP cross-cloud APIs
// (oauth2 + spanner + bigtable) must travel via vsock to the parent
// EC2 host, where AWS's `vsock-proxy` daemon (shipped with
// aws-nitro-enclaves-cli) does the real DNS+TCP egress and pumps
// bytes back.
//
// Architecture:
//
//	enclave HTTP client
//	  └── vsockhttp.Transport.DialContext(host, port)
//	        └── vsock.Dial(parent CID 3, vsock_port_for_host)
//	              └── parent's vsock-proxy listening on that port
//	                    └── TCP dial to host:443 with TLS passthrough
//
// TLS is end-to-end between the enclave and the upstream API — the
// parent's vsock-proxy never sees plaintext. The trust property is
// preserved at the prompt-content level.
//
// The Tunnel list MUST stay in lockstep with:
//   - parent's /etc/nitro_enclaves/vsock-proxy.yaml allowlist
//   - tools/deploy-aws-nitro.sh user-data that writes that yaml
//
// Unlisted hostnames fail closed with vsockhttp.UnconfiguredHostError;
// adding a new provider is a 2-line edit here + a 1-line edit on the
// parent yaml.

package llm

import (
	"net/http"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/vsockhttp"
)

// awsProviderTunnels maps every upstream hostname the multi-provider
// enclave dials to a parent vsock-proxy port.
//
// Port assignments are deterministic (8003-8099 reserved for upstream
// tunnels) so the parent can build its yaml from this list at deploy
// time without an out-of-band lookup. We don't reuse port 8001 (that's
// the enclave's own vsock listener) or 9100 (parent's bootstrap RPC).
//
// CID is always 3 — the well-known parent CID for Nitro Enclaves.
var awsProviderTunnels = []vsockhttp.Tunnel{
	// LLM provider direct-API endpoints (mirrors the byok.go
	// directBaseURL switch + tinfoil_attest.go fixed host).
	{Host: "api.anthropic.com", CID: 3, Port: 8003},
	{Host: "api.openai.com", CID: 3, Port: 8004},
	{Host: "api.cerebras.ai", CID: 3, Port: 8005},
	{Host: "api.deepseek.com", CID: 3, Port: 8006},
	{Host: "api.mistral.ai", CID: 3, Port: 8007},
	{Host: "api.moonshot.ai", CID: 3, Port: 8008}, // kimi
	{Host: "generativelanguage.googleapis.com", CID: 3, Port: 8009},
	{Host: "api.z.ai", CID: 3, Port: 8010},
	{Host: "api.together.xyz", CID: 3, Port: 8011},
	{Host: "api.fireworks.ai", CID: 3, Port: 8012},
	{Host: "api.x.ai", CID: 3, Port: 8013}, // grok
	{Host: "api.novita.ai", CID: 3, Port: 8014},
	{Host: "api.redpill.ai", CID: 3, Port: 8015}, // phala
	{Host: "api.siliconflow.com", CID: 3, Port: 8016},
	{Host: "inference.tinfoil.sh", CID: 3, Port: 8017},
	{Host: "api.venice.ai", CID: 3, Port: 8018},
	// 2026-05-11 batch (3 new providers; all OpenAI-compatible).
	{Host: "api.parasail.io", CID: 3, Port: 8019},
	{Host: "lightning.ai", CID: 3, Port: 8020},
	{Host: "api.gmi-serving.com", CID: 3, Port: 8021},
	{Host: "api.deepinfra.com", CID: 3, Port: 8022},
	{Host: "api.tokenfactory.nebius.com", CID: 3, Port: 8023},
	{Host: "api.minimax.io", CID: 3, Port: 8024},
	{Host: "api.friendli.ai", CID: 3, Port: 8025},
	{Host: "inference.baseten.co", CID: 3, Port: 8026},
	{Host: "tinker.thinkingmachines.dev", CID: 3, Port: 8039},
	{Host: "pass.wafer.ai", CID: 3, Port: 8027},
	{Host: "api.inference.crusoecloud.com", CID: 3, Port: 8028},
	{Host: "inference.makora.com", CID: 3, Port: 8029},

	// GCP cross-cloud APIs. The AWS-side enclave authenticates with
	// the cross-cloud SA key (received in BootstrapData) and reads
	// the credit ledger from Spanner + writes generation logs to
	// Bigtable. oauth2.googleapis.com mints access tokens from the
	// SA's RS256-signed JWT.
	{Host: "oauth2.googleapis.com", CID: 3, Port: 8030},
	{Host: "spanner.googleapis.com", CID: 3, Port: 8031},
	{Host: "bigtable.googleapis.com", CID: 3, Port: 8032},
	{Host: "bigtableadmin.googleapis.com", CID: 3, Port: 8033},
	// storage.googleapis.com (port 8034) is added in enclavetls's own
	// tunnel list (gcscache_http_aws.go); not used by the LLM clients
	// so we deliberately leave it off here.
	// cloudkms.googleapis.com (port 8035) is reached only by BYOK
	// envelope-unwrap; byokcache builds its own client. Listed here
	// for documentation of the parent's expected vsock-proxy port
	// map but unused in this file.
}

// defaultHTTPClient returns an http.Client that dials each upstream
// over vsock per the awsProviderTunnels map. Hosts not in the map
// fail with UnconfiguredHostError — the explicit allowlist is part of
// the trust story (the enclave can only reach hosts the parent's
// yaml has authorized).
func defaultHTTPClient() *http.Client {
	return vsockhttp.NewClient(awsProviderTunnels)
}

// AWSProviderTunnels exposes the tunnel list so deploy tooling can
// generate the parent's vsock-proxy.yaml from the same source of
// truth. Returns a copy so callers can't mutate the package-level
// constant.
func AWSProviderTunnels() []vsockhttp.Tunnel {
	out := make([]vsockhttp.Tunnel, len(awsProviderTunnels))
	copy(out, awsProviderTunnels)
	return out
}
