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

## Redirect compatibility audit (2026-11-16 UTC)

The first live smoke covered only five unauthenticated metadata endpoints. That
was reachability evidence, not a complete redirect compatibility test. The
optional `TestProviderRedirectAuditLive` now derives ordinary API endpoints from
the provider registry and legacy URL switch, plus explicit native API paths.
It sends empty JSON POSTs through the production guarded client, with redirects
disabled and four concurrent requests. It sends no prompts or model selection.
Only status, sanitized redirect location and transport errors are recorded;
response bodies are discarded. Provider availability is not a normal CI gate.

After explicit operator approval, the authenticated audit used 104 existing
provider credentials, each only on its corresponding endpoint. Credentials
were passed to the compiled test over stdin, not persisted in logs, command
arguments or the repository. All 119 probes had an available credential; a
transport failure does not establish that the credential reached the server.

| Result | Endpoints |
| --- | ---: |
| Redirect (HTTP 3xx) | 0 |
| HTTP 400 / 422, consistent with an empty request | 100 |
| HTTP 200 (body not interpreted) | 2 |
| HTTP 401 / 403 | 2 |
| HTTP 404 / 410 | 13 |
| HTTP 502 | 1 |
| Connection failure | 1 |

Findings requiring separate availability or valid-request checks:

- Hixtube could not connect. A standard HTTPS curl probe without the guarded
  transport also failed to connect, so this was not isolated to the new guard.
- 0G returned HTTP 502 after authentication was attached; the request reached
  an upstream HTTP server, rather than being rejected by the destination guard.
- Riverflow returned 401 and ScaleDown returned 403. Those responses do not
  prove authentication succeeded. The 404/410 responses also do not establish
  that a real model request works; an empty request has no model to route.

No observed redirect requires a compatibility exception. This snapshot does
**not** prove that every model, region, valid inference request or asynchronous
poll/download path is redirect-free. Dedicated encrypted/attested helper paths
(Privatemode, Maple and NEAR), account-dynamic Cloudflare URLs, cloud-native
IAM/SigV4 paths and all regional variants are not covered by this ordinary-HTTP
sweep. Keep their existing tests and cloud rollout canaries. Never broaden the
allowlist or follow a credential-bearing redirect to compensate for a provider
outage or an inconclusive empty-request probe.
