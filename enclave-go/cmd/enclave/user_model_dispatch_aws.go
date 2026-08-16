//go:build cloud_aws

package main

// Nitro enclaves have no NIC or DNS. Their parent exposes only a measured,
// static per-host vsock allowlist, so arbitrary owner endpoints cannot be
// reached or IP-pinned on this plane.
func userModelDispatchSupported() bool { return false }
