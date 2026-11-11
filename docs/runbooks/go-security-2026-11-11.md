# Go security toolchains, 2026-11-11

The official Go advisory [GO-2026-6859](https://pkg.go.dev/vuln/GO-2026-6859),
published at 02:51:11 UTC, describes an HTTP/1 server panic when an exceeded
MaxBytesReader limit sets a connection header concurrently with a handler's
response-header write. This is not evidence of exploitation or the cause of
the Maple provider errors.

CI run 42955691645 on trust-only PR749 failed its existing reachable Go
vulnerability scan with Go 1.26.10. Earlier source CI preceded the advisory.
Do not suppress the finding, retry unchanged CI, or qualify an old image by
running its source through only a newer CI toolchain.

The main enclave, sidecar and parent-pump builders and CI use Go 1.26.11.
The separately built PrivateMode helper uses Go 1.27.4. Both are patch-level
updates in their existing release lines. Official Docker Hub index digests:

- `1.26.11-bookworm`: `sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0`
- `1.27.4-bookworm`: `sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea`

The PrivateMode source archive, reviewed patch, dependency override and
policy manifest remain unchanged. Maple source and approved upstream
measurements remain unchanged. New gateway images still require full CI,
immutable build provenance, independent measurement verification, published
signed trust and the ordinary guarded regional rollout. Already-built
1.26.10/1.27.3 images do not acquire this fix from a later merge.

GCP is the immediate deployment priority. Updating shared build definitions
does not authorize an AWS or Azure production rollout while those are deferred.
