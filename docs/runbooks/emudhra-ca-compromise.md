# eMudhra CA response, 2026-10-20

## Scope

Go 1.26.10 rejects the compromised intermediate keys (CVE-2026-111943).
All enclave Dockerfiles, parent pump and both Go modules require that release.
The immutable builder digest is
`sha256:ee3901c61e423732605a51f1b8157c849ec01194ea0a274213b5202b2c11e7bf`.

Both root paths must be handled: `emSign ECC Root CA - G3` and the
`AAA Certificate Services` cross-sign. Debian build steps explicitly distrust
those roots even when the package mirror has not yet published its update.
Keep normal TLS verification and attestation-bound public-key verification.

References:
* https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
* https://go.dev/issue/82345
* https://emudhra.we-have-a-problem.com/

## Regression checks

`go test -tags cloud_gcp,llm_multi ./internal/llm -run 'TestEMudhra|TestValidTLS'`
tests all twelve historical TLS chains offline, using the old roots deliberately
to prove Go rejects compromised keys independently of the system bundle.
Fixtures contain public certificates only. Time is frozen within validity.

Run the existing full build-tag matrix, sidecar and parent tests. Test outgoing
HTTPS with no credentials against the two researcher endpoints below: both must
fail with a certificate verification error, not a timeout or DNS error. Genuine
provider HTTPS handshakes must succeed; an unauthenticated 401/404 is acceptable.

* https://dv-g3b-emudhra.we-have-a-problem.com/
* https://dv-g3b-aaa-emudhra.we-have-a-problem.com/

## Release

Merge through CI. Use the existing GCP attested release workflow, AWS isolated
candidate/PCR0 transition runbook, and Azure measured-policy release tool.
Refresh the DNS reconciler too. Do not replace serving capacity before its
new measurement is accepted, and do not bypass cloud admission/health gates.

Updating source or rebuilding a tag does not patch a running image. Record the
release SHA and actual image digest/measurement per cloud, verify attestation,
and run regional health and product smoke checks before declaring completion.
The matching quill-router change updates certifi and the control-plane images.

## Laptop

Update Homebrew `ca-certificates` and `uv` without upgrading unrelated
dependents. macOS curl can use the patched bundle via `~/.curlrc`:

```text
cacert = "/opt/homebrew/etc/ca-certificates/cert.pem"
```

This protects normal curl invocations, including `/usr/bin/curl`. `curl -q`,
other users, and software reading `/etc/ssl/cert.pem` directly are not covered.
Updating that protected file requires administrator authorization. Do not
claim the per-user curl setting updates the OS trust store or every application.
