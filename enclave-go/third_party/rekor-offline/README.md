# Offline Rekor verification subset

Source: `github.com/sigstore/rekor@v1.5.0`, commit
`fe9717fd6ee4cfecedc30e5fd64c9872bc2ac61c`, Apache-2.0 (LICENSE included).
Module checksum: `h1:rL7SghHd5HLCtsCrxw0yQg+NczGvM75EjSPPWuGjaiQ=`.

This is the runtime and verification-test package closure used by our Sigstore bundle verifier.
No signature, checkpoint, inclusion-proof, SET, schema or key-verification
implementation has been rewritten. The only code change is omission of two
unused online helpers (`ProveConsistency` and `VerifyCurrentCheckpoint`) and
their generated HTTP-client imports from `pkg/verify/verify.go`. Their caller
tests/mock are omitted too; upstream inclusion and checkpoint tests remain.
All other retained source files are byte-for-byte upstream copies.

Those online helpers pulled go-openapi's tracing HTTP client and OpenTelemetry
into the sidecar even though our verification path never called them. Missing
online APIs now cause compile errors, not silently successful no-op checks.
The sidecar still fetches evidence and trusted roots using its existing clients;
"offline" refers to these proof-verification functions, not the whole sidecar.

From `enclave-go`, regenerate or verify the exact source subset:

```sh
go run ./tools/rekor-offline
go run ./tools/rekor-offline -check
```

The generator checks the upstream module checksum and exact removed declaration
set. CI checks source equality, upstream Sigstore verification tests, sidecar
tests and telemetry absence from the final runtime executables. Upstream updates
require explicitly reviewing the pin, generated diff and all these gates.

`go.mod`/`go.sum` are unchanged upstream dependency metadata. The generated HTTP
client remains for upstream Sigstore tests that construct signed entries, but
is not imported by runtime verification. The go-openapi runtime's model
interfaces are still required; its instrumented `runtime/client` package is not.
Test/tool dependencies in a module graph are not evidence of a linked SDK;
the release gate inspects actual Go build info. Do not run `go mod tidy` inside
this pinned subset: its metadata intentionally matches upstream.
