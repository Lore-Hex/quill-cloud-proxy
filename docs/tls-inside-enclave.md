# TLS termination inside the enclave

The V1 production chain terminates TLS at the ALB:

```
client ──TLS──► ALB ──HTTP──► parent ──vsock──► enclave (parses HTTP)
                ▲ AWS-managed cert
                ▲ Plaintext from this hop onward
```

The "PCR0-measured binary is the boundary" trust property is therefore
weaker than advertised: AWS infrastructure (ALB internals + parent process
memory, briefly) sees prompt content in plaintext. We're moving TLS
termination INSIDE the enclave so the only code that ever holds prompt
bytes is the attested binary.

## Target architecture

```
client ──TLS──────────────────────────────────────────► ENCLAVE (terminates TLS)
                                                         (PCR0-measured)
        ▲ NLB does TCP passthrough — no decryption
        ▲ Parent is a dumb byte pump, never decrypts

  └── ALB, FastAPI, /admin/usage, /trust, /health: same as today, on a
      separate hostname (admin.quill.lorehex.co). Those endpoints don't
      see prompt content.
```

## Migration phases

### Phase 1 — enclave-side scaffolding (this PR)

- New package `internal/enclavetls`: generates a P-256 ECDSA keypair and a
  self-signed cert at enclave startup, wraps the vsock listener with
  `tls.NewListener`. Key never touches disk.
- Behaviour gated on `QUILL_ENCLAVE_TLS=true`. Default off so the existing
  HTTP-over-vsock chain keeps working until Phase 2 lands.
- Cert fingerprint is logged to stderr at startup and (when run with
  `--debug-mode`) visible on the cloud-init log. Phase 3 will surface it
  via an `/attestation` endpoint so callers can fetch + verify.

The cert rotates on every enclave restart — clients should NOT statically
pin it. The trust story relies on:
1. Connect over TCP-passthrough.
2. Fetch attestation document (Phase 3 endpoint).
3. Verify PCR0 matches the trust page's published value.
4. Verify the cert presented in the TLS handshake is the one named in the
   attestation document.

That chain — PCR0 → attestation doc → cert fingerprint → TLS session —
is the same trust shape the Brave nitriding-daemon uses.

### Phase 2 — parent + Terraform

- **Parent**: replace the `/v1/chat/completions` FastAPI handler with a
  raw TCP listener on a new port (`8444`). Each accepted connection opens
  a vsock to the enclave and bidirectionally pumps bytes — no parsing, no
  inspection, no buffering of body. The existing `/admin`, `/trust`,
  `/health` keep their current FastAPI listener on `8443`.
- **Terraform**:
  - Add an NLB targeting `parent:8444` for the TLS-passthrough path.
  - Front it with `api.quill.lorehex.co` (CNAME from Cloudflare).
  - Keep ALB on `admin.quill.lorehex.co` for non-prompt paths.
  - Drop the ACM cert from the prompt-path load balancer (NLB does no TLS).

### Phase 3 — attestation, cert binding, trust page

- **`/attestation` endpoint** inside the enclave: returns the current
  Nitro NSM attestation document. The doc commits to the current PCR0
  AND the public key of the TLS cert (via the `public_key` field of
  `attestation_document`). Clients verify both before sending prompts.
- **NSM library**: depend on `github.com/hf/nsm` for the ioctl wrapper.
  Tiny dependency.
- **Trust page**: surface a "current cert fingerprint + PCR0 binding"
  block alongside the static PCR0. Verify-script published in the same
  repo.
- **Reproducible builds**: pin Docker base image digests, Go module
  versions, lock the build environment so PCR0 is deterministic across
  runs of the same source. Already mostly there; tighten to be sure.

## Inspirations from brave/nitriding-daemon

What we're adopting:
- Internal TLS termination with self-signed cert (Phase 1).
- Attestation doc bound to the cert's public key (Phase 3).
- Reproducible builds for stable PCR0.

What we're skipping (for now):
- TAP interface inside the enclave (we use vsock + a vsock-tcp proxy on
  the parent — different shape, same outcome).
- Let's Encrypt automation (the cert rotates per boot anyway; LE adds
  complexity for marginal benefit when clients verify via attestation).
- Horizontal-scaling sync (we're a single-host V1).

## Verifying

After Phase 1 lands, the smoke test (with the flag flipped) should:

```bash
# Phase 1 verification: enclave terminates TLS but parent still wraps HTTP.
# This won't work end-to-end yet (parent + NLB pieces are Phase 2). The
# enclave-side check is whether the cert fingerprint appears in
# /var/log/quill-bringup.log on host bring-up:
ssh quill-host 'sudo grep enclavetls.cert_fingerprint /var/log/quill-bringup.log'
```

After Phase 2 + 3 the smoke test becomes:

```bash
# 1. Pull attestation doc; verify PCR0 + extract cert fingerprint.
curl -s https://api.quill.lorehex.co/attestation | python verify-attestation.py
# 2. Confirm the live TLS handshake presents that exact cert.
echo | openssl s_client -servername api.quill.lorehex.co \
        -connect api.quill.lorehex.co:443 2>/dev/null \
  | openssl x509 -outform DER | shasum -a 256
```
