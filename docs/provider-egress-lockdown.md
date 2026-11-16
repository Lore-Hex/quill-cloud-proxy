# Provider egress lockdown

The measured gateway enforces a compiled allowlist for ordinary provider HTTPS
requests on GCP, Azure and AWS. This is not an environment switch. Adding a
provider destination requires a source change, tests and a new attested image.

## Boundary

- Exact hostnames only, HTTPS on port 443. No wildcard provider domains,
  caller-supplied hosts, alternative ports, URL credentials or Host overrides.
- Every request is checked, including requests over reused connections.
- Redirects are refused, including redirects to another approved provider.
- Environment proxy settings are ignored. Direct connections resolve DNS once,
  reject the entire answer if any address is private or reserved, and dial only
  the vetted addresses while retaining normal hostname/certificate validation.
- The existing TLS certificate receipt collection and connection pooling remain.
- AWS additionally retains its fixed vsock tunnels and lack of a network device.
- Azure Foundry and Databricks use the specific reviewed TR account hostnames,
  not suffixes permitting arbitrary customer workspaces.

The policy lives in `enclave-go/internal/llm/provider_egress.go` and includes the
immutable `internal/directproviders` registry plus reviewed legacy/native API
hosts. Tests check the legacy endpoint switch against the policy. New Vertex
regions and Databricks workspaces require explicit hostname entries.

## Separate, bounded paths

This is **provider-request enforcement**, not a claim of a whole-VM outbound
firewall on GCP or Azure. Those clouds retain a network stack. The following
necessary paths have distinct policies and must not be confused with ordinary
inference dispatch:

- Vertex token acquisition permits only GET of the exact GCE metadata token
  endpoint, with the Google metadata header and no body or other headers.
- Tinfoil retains attestation and certificate pinning to its exact inference
  host. NEAR uses only its compiled model-to-domain map and a single verified
  connection. Both reject HTTP downgrades and destination changes before I/O.
- Privatemode and Maple retain their dedicated pinned encrypted clients. Their
  endpoints are deliberately absent from the ordinary HTTPS allowlist.
- Caller-provided image/video inputs retain their separate SSRF-checked fetch
  paths. Provider-generated signed CDN URLs use a separate public-IP-checked,
  origin-pinned, GET-only download client with no inference body or credentials.
  They cannot add a destination to the inference allowlist. Nitro does not gain
  arbitrary CDN tunnels. Artifact URLs are not themselves a confidentiality
  guarantee; do not put sensitive text in URLs.
- Bootstrap, control-plane settlement, certificate issuance and attestation
  collateral keep their existing dedicated transports. They are not inference
  destinations and have not been redirected through the provider client.

Custom/user-provided model execution was removed in #676. GCP/Azure previously
had general network-capable provider transports; the historical owner-endpoint
SSRF guard was not a provider-domain allowlist. AWS's fixed allowlist remained
in place. This change closes the ordinary provider-client gap rather than
claiming to restore a disabled whole-enclave firewall.

## Release checks

Run the full Go build-tag matrix, including the negative egress tests, and the
existing AWS vsock map parity checks. Preserve normal CI, measured builds,
attestation publication, regional canary/health checks and rollback retention.
Do not widen the policy automatically after a failed provider probe. Investigate
and review a necessary hostname change as another measured release.
