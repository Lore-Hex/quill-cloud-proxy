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
// ORDER HERE IS NOT THE FAILOVER ORDER — this is only the set of hosts the
// enclave is PERMITTED to dial. The order it actually tries them in comes from
// TR_CONTROL_PLANE_BASE_URL (see endpoints.go).
//
// This list is compiled into the binary, so it is inside the EIF and therefore
// MEASURED BY PCR0. Adding a host later costs an image rebuild and a fleet-wide
// re-pin of every PCR0 assertion. Only the billing authority belongs here;
// observer/status services must not receive money-path RPCs.
var trControlPlaneTunnels = []vsockhttp.Tunnel{
	{Host: "trustedrouter.com", CID: 3, Port: 8040},
}

func newControlPlaneHTTPClient() *http.Client {
	// The vsock dialer's failures are plain syscall errors, not *net.OpError,
	// so they are tagged here rather than classified by shape later — a
	// shape-based check would miss the most likely real failure, the parent's
	// vsock-proxy being down.
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: markDialFailures(vsockhttp.NewTransport(trControlPlaneTunnels)),
	}
}
