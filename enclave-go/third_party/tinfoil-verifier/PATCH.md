# Local patch to tinfoil verifier v0.12.0

This directory is a vendored copy of
`github.com/tinfoilsh/tinfoil-go/verifier` at upstream version `v0.12.0`.
`LICENSE` is preserved from that release.

## Why this fork exists

The attestation sidecar runs inside an AWS Nitro enclave, which has no network
interface or DNS resolver. Its outbound connections must travel over vsock to
byte-pipe proxies on the parent instance. HTTP requests can use a custom
`http.DefaultTransport`, but the verifier's final TLS public-key binding check
called `tls.Dial` directly and therefore attempted DNS inside the enclave.

## Exact upstream source change

Only `client/enclave_other.go` differs from upstream code:

1. It exports a package-level `DialTLSContext` function variable whose default
   implementation calls `tls.Dial(network, addr, cfg)` unchanged.
2. `enclaveValidPubKey` calls `DialTLSContext("tcp", addr, &tls.Config{})`
   instead of calling `tls.Dial("tcp", addr, &tls.Config{})` directly.

No verification logic was changed. In particular, TLS certificate validation,
certificate fingerprint extraction, and the comparison
`certFP != enclaveVerification.TLSPublicKeyFP` remain in their original order
and are unchanged. There is no fallback on dial failure.

The embedding sidecar assigns the hook during startup. Its implementation dials
the allowlisted parent vsock proxy, wraps that byte stream with `tls.Client`,
preserves `tls.Dial`'s `tls.Config` and inferred `ServerName` behavior, and
completes the TLS handshake inside the enclave before returning. The parent
does not terminate TLS.

To audit this fork against the cached upstream module, run:

```sh
diff -ru --exclude=PATCH.md \
  "$(go env GOMODCACHE)/github.com/tinfoilsh/tinfoil-go/verifier@v0.12.0" \
  enclave-go/third_party/tinfoil-verifier
```
