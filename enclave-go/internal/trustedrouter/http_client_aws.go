//go:build cloud_aws

// AWS Nitro variant of the control-plane HTTP client. Routes
// `trustedrouter.com` (the canonical TR control-plane hostname) over
// the parent's vsock-proxy on port 8040.
//
// Why a separate tunnel list from internal/llm/http_client_aws.go:
// avoids a circular import (internal/llm already depends on
// internal/trustedrouter via multi.go). Both lists must stay in
// lockstep with the parent's vsock-proxy systemd units in
// tools/deploy-aws-nitro.sh — adding a TR control-plane endpoint
// is a 1-line edit here + a 1-line write_vsock_unit call there.

package trustedrouter

import (
	"net/http"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/vsockhttp"
)

// trControlPlaneTunnels is the allowlist of TR control-plane hostnames
// the enclave is permitted to dial. trustedrouter.com points at the
// global GCP LB fronting the FastAPI control plane (api-key lookups,
// reservation/settle, byok envelope unwrap).
var trControlPlaneTunnels = []vsockhttp.Tunnel{
	{Host: "trustedrouter.com", CID: 3, Port: 8040},
}

func newControlPlaneHTTPClient() *http.Client {
	c := vsockhttp.NewClient(trControlPlaneTunnels)
	c.Timeout = 30 * time.Second
	return c
}
