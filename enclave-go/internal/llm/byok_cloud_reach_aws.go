//go:build cloud_aws

package llm

// Nitro gateways egress only through an exact list of vsock tunnels, so the
// customer-chosen hosts of native cloud BYOK credentials are unreachable.
const cloudBYOKReachable = false
