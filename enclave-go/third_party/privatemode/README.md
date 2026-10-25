# Privatemode client build

Build only the MIT-licensed client from `privatemode-public` release v1.60.0,
commit `317d813671769c16238b8e93245e5e2e06060a92`. The Dockerfiles pin both
the source archive SHA-256 and the Go 1.26.10 builder image. Go module
checksums remain enabled. The runtime includes the upstream MIT notice.

The vendor's v1.60.0 binary uses Go 1.26.8. We build the same client with the
patched toolchain instead of importing that binary. `control-plane-limits.patch`
adds a 4 MiB response limit and a 30 second deadline to attestation/key-exchange
HTTP calls, plus a two minute deadline around secret refresh. These limits do
not apply to inference streams. The tests beside the patch are copied into
the extracted source and run during every build.

Attestation, expected-manifest matching, nonce checks, encryption, mesh
certificate verification and strict GPU OCSP policy are unchanged. There is
no runtime manifest download or automatic acceptance of new measurements.

Rebuild the client stage without provider credentials:

```sh
docker build --platform linux/amd64 --target privatemode \
  -f enclave-go/Dockerfile.enclave.gcp.multi enclave-go
```

The reviewed manifest and model allowlists are in `internal/privatemode`.
Release evidence and the policy-reproduction gate are documented in
`docs/runbooks/privatemode.md` and its dated review. Building successfully is
not sufficient to authorize new remote measurements.
