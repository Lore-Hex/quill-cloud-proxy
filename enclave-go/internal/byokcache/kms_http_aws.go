//go:build cloud_aws

// vsock-tunneled HTTP client for the BYOK Google-KMS unwrap path on
// the AWS-side enclave.
//
// BYOK customers wrap their data-encryption keys with their own GCP
// KMS key, and the enclave decrypts envelopes by calling
// cloudkms.googleapis.com:Decrypt. On AWS there's no NIC; the call
// must travel via vsock to the parent's vsock-proxy daemon.
//
// We also need oauth2.googleapis.com tunneled because the cross-cloud
// SA-key flow exchanges a signed JWT there for a cloudkms-scoped
// access token. The metadata.google.internal path (the GCP-side
// token source) returns ErrNoMetadata on AWS.
//
// Ports must match the parent's /etc/nitro_enclaves/vsock-proxy.yaml
// (configured by tools/deploy-aws-nitro.sh).
package byokcache

import (
	"net/http"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/vsockhttp"
)

var byokTunnels = []vsockhttp.Tunnel{
	{Host: "oauth2.googleapis.com", CID: 3, Port: 8030},
	{Host: "cloudkms.googleapis.com", CID: 3, Port: 8035},
}

// NewVsockKMSClient returns an http.Client that dials each upstream
// over vsock per the byokTunnels map. Used by GoogleKMSUnwrapper on
// the AWS Nitro enclave path; the GCP path (kms_http_gcp.go) just
// returns a stdlib client.
func NewVsockKMSClient() *http.Client {
	c := vsockhttp.NewClient(byokTunnels)
	c.Timeout = 30 * time.Second
	return c
}
