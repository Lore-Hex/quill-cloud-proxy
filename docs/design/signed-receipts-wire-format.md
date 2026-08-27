# Signed inference receipts — wire format v1

**Spec id:** `inference-receipt/1` (claim `rv: 1`)
**Media type:** `application/inference-receipt+jws`
**Status:** implementing; nothing is advertised until the release records say so.

## 1. The law (read first)

- **Opt-in.** No request gets a receipt unless it asked with the
  `x-inference-receipt` header.
- **Never stored.** The enclave signs and forgets. There is no fetch-by-id, no
  receipt database, and none may ever be added — a receipt exists only in the
  response that carried it. (The append-only key log stores public key
  material and attestation documents, never receipts.)
- **One signer.** The enclave signs every production receipt. There is no
  control-plane signer; control-plane inference is a local/test surface and
  ignores the header.
- **The receipt chunk is the last data event before `data: [DONE]`.** Never
  after it. A stream that errors or truncates gets no receipt.
- **Claims name what was verified, never a privacy property.** A receipt
  proves what was served. It does not prove what was kept, and it does not
  prove who else saw it.

## 2. What a receipt is

A compact or flattened JWS, `alg: EdDSA` (Ed25519), signed by a per-instance
key generated inside the enclave at boot from the hardware-seeded RNG. The
key's public half is committed inside the enclave's attestation document, so a
receipt chains: signature → key → attestation → published measurement →
source commit.

### 2.1 Opt-in request header

```
x-inference-receipt: true
x-inference-receipt: <nonce: 1-88 chars of [A-Za-z0-9_-]>
```

A nonce is REQUIRED for any receipt that will be shown to a third party: the
`nonce` claim echoes it, and it is the only freshness a relying party can
trust. `true` yields a receipt with no `nonce` claim. Oversized or
ill-charactered values are a 400. The header is never forwarded upstream.

### 2.2 Delivery

- **Non-streaming:** response header `x-inference-receipt: <compact JWS>`.
  Compact form omits the attestation document (header-size budgets); the
  `att_sha256` claim pins the exact document, fetchable at
  `GET /receipt-attestation` on the same origin while the instance lives and
  from the key log forever.
- **Streaming:** one additional `chat.completion.chunk` with `"choices": []`
  and top-level key `inference_receipt` whose value is a flattened JWS with
  the attestation document embedded in the protected header. It MUST be the
  final data event before `data: [DONE]`. Verifiers MUST reject a receipt if
  any data event other than `[DONE]` follows it.

### 2.3 Instance key discovery

Anonymous `GET /receipt-key` publishes the current enclave instance's public
receipt key and its cached key-binding attestation as single-line JSON with
`Content-Type: application/json` and `Cache-Control: no-store`:

```json
{"kid":"<b64url SHA-256 of raw pubkey>","jwk":{"kty":"OKP","crv":"Ed25519","x":"<b64url pubkey>"},"att":"<JWT verbatim, or b64url COSE>","att_kind":"gcp-cs-jwt|aws-nitro-cose|azure-maa-jwt"}
```

The field order above is fixed. `att` uses exactly the same encoding as the
flattened JWS protected header: GCP and Azure JWTs are verbatim, while the AWS
Nitro COSE document is unpadded base64url. The endpoint has the same
instance-scoped, no-caller-nonce, no-TLS-exporter semantics as the cached key
attestation. It returns 503 until a key-binding document has been minted and
404 when receipts are disabled.

`GET /receipt-attestation` remains available for existing clients and serves
the same cached document in its legacy raw form with `x-receipt-att-kind`.

## 3. Claims

```json
{
  "rv": 1,
  "iss": "https://api.trustedrouter.com",
  "iat": 1756223999,
  "jti": "chatcmpl-…",
  "gen": "gen-…",
  "nonce": "kZ8v…",
  "route": "chat.completions",
  "req":  { "alg": "sha256", "hash": "<b64url 32B>", "of": "body" },
  "resp": { "alg": "sha256", "hash": "<b64url 32B>", "of": "sse-data-v1", "events": 143 },
  "model": { "requested": "…", "selected": "…", "provider": "…", "endpoint": "…" },
  "upstream": { "tier": "tee-verified", "policy": "chutes-tdx-nvidia-e2e-v1",
                "verified_at": 1756223940, "verification_expires_at": 1756224240 },
  "att_sha256": "<b64url 32B, header delivery only>"
}
```

- `rv` REQUIRED, integer 1.
- `iss` REQUIRED: canonical API origin of the serving plane.
- `iat` REQUIRED: Unix seconds at signing. Verifiers reject missing `iat` and
  allow at most 60 s of future skew.
- `jti` REQUIRED: the response's own id — receipt↔response cross-check.
- `gen` OPTIONAL: generation id. Non-streaming only (streaming settles after
  `[DONE]`; the id does not exist when the receipt is signed).
- `nonce` OPTIONAL: verbatim echo of the request header value when not `true`.
- `route` REQUIRED: `"chat.completions"` or `"responses"`.
- `req` REQUIRED, `resp` REQUIRED: hash records, §4.
- `model` REQUIRED: `requested` (pre-alias), `selected`, `provider`,
  `endpoint` exactly as the router metadata reports them.
- `upstream` REQUIRED: §5.
- `att_sha256`: present in header-delivered (compact) receipts only.

## 4. Hash domains

All SHA-256, base64url-unpadded.

- `req.hash`, `of: "body"` — the exact request body bytes received from the
  client. No headers, no normalization.
- `resp.hash`, `of: "body"` (non-streaming) — the exact response body bytes.
  Possible because the receipt travels in a header, outside its own pre-image.
- `resp.hash`, `of: "sse-data-v1"` (chat streaming) — with `D_1 … D_n` the
  `data:` payload byte-strings of every SSE event in wire order, excluding the
  receipt event and `[DONE]`:
  `SHA-256(D_1 ‖ 0x0A ‖ D_2 ‖ 0x0A ‖ … ‖ D_n ‖ 0x0A)`.
  Each payload contributes its own trailing 0x0A (n=0 hashes empty).
  Injectivity requires LF-free payloads; the enclave's payloads are
  single-line JSON by construction, and a stream that would violate this MUST
  NOT carry a receipt.
- `resp.hash`, `of: "sse-events-v1"` (Responses API streaming) — events carry
  names: `SHA-256(name_1 ‖ 0x0A ‖ data_1 ‖ 0x0A ‖ … )`, an (name, data) pair
  per event, unnamed events contribute an empty name. Same exclusions.

The hash is computed over post-coalescing bytes — what the client actually
received — and is recomputable from any captured stream because SSE parsers
preserve payloads even where they normalize framing.

## 5. Upstream tiers

Tier values name the verification mechanism the enclave performed for THIS
request. They never name a privacy property.

- `"tee-verified"` — the enclave verified upstream TEE evidence under the
  named `policy`, and that verification (`verified_at`) was unexpired
  (`verification_expires_at`) when the request was served. Verifiers MUST
  check `verified_at ≤ iat < verification_expires_at`. Registered policies:
  `chutes-tdx-nvidia-e2e-v1`, `tinfoil-snp-dual-source-v1`.
- `"tls-webpki"` — the upstream was reached over WebPKI-validated TLS and
  nothing more. `cert_sha256` (leaf fingerprint of the connection that served
  this request) is included when per-request attribution is certain and
  omitted otherwise — never guessed.

### 5.1 `cert_sha256`

For `tls-webpki`, `cert_sha256` is SHA-256 over the DER bytes of the peer leaf
certificate on the TLS connection that served this specific request, encoded
as unpadded base64url. Connection pooling, retries, and redirects do not relax
that binding: if the serving connection cannot be attributed with certainty,
the claim is omitted. It is never guessed from a newly dialed or previously
used connection, and it is never present on a `tee-verified` upstream block.

## 6. JWS envelope

Protected header:

```json
{ "alg": "EdDSA", "typ": "inference-receipt+jws",
  "kid": "<b64url SHA-256 of raw pubkey>",
  "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "<b64url pubkey>" },
  "att": "<attestation doc: JWT verbatim, or b64url COSE>", 
  "att_kind": "gcp-cs-jwt" | "aws-nitro-cose" | "azure-maa-jwt" }
```

`att`/`att_kind` appear in flattened (streaming) receipts; compact (header)
receipts omit them and carry `att_sha256` in the claims instead. `att_kind` is
authoritative for parsing — never guess by shape.

## 7. Key commitment

```
C = SHA-256("inference-receipt-key-v1" ‖ 0x00 ‖ raw 32-byte public key)
```

- GCP: `hex(C)` as an additional Confidential Space nonce entry, positioned
  after the server-derived entries and before the caller nonce.
- AWS: UserData is 128 bytes when a receipt key exists:
  `certFP(32) ‖ deviceHash(32) ‖ exporter-or-zeros(32) ‖ C(32)`.
- Azure: `runtime_data.receipt_key_fp = hex(C)` (alphabetically last).

Verifier rule: recompute C from the header `jwk` and check **set membership**
among the document's committed values. The domain-separated pre-image cannot
collide with cert, device, or exporter hashes, so position is irrelevant.

The key-binding attestation is minted at boot with no caller nonce and no
exporter: it certifies a durable key, not a live channel. Session binding
remains the `/attestation` + RFC 9266 + fresh-nonce flow.

## 8. Verification procedure (offline)

1. Verify the JWS signature with header `jwk`; check `kid = B64URL(SHA-256(x))`.
2. Obtain the attestation: embedded `att`, or (compact) fetch by `att_sha256`
   from `/receipt-attestation` or the key log; verify its signature chain to
   the cloud root (issuer-routed, never shape-routed).
3. Check `C ∈` committed slots (§7).
4. Extract the measurement and require membership in the published release
   history (`/trust/*-release.json` and the accepted-measurement files).
5. Check `iat` skew; if a `nonce` was sent, require the echo.
6. Recompute `req.hash` and `resp.hash` from held bytes per §4.

Steps 1–3 and 5–6 are fully offline; step 4 needs only the published trust
material, the same dependency all attestation verification already has.

## 9. What a receipt does NOT prove

- **Not a confidentiality proof.** A relay that forwarded your traffic holds a
  valid receipt and also read everything. "Am I talking directly to the
  enclave" is answered only by the live `/attestation` flow with a fresh nonce
  and exporter binding — never by a receipt.
- **Not a retention statement.** Neither TR's nor the provider's.
- **Not a model-weights identity proof.** `model.selected` is the routing
  claim the enclave acted on; weight-level identity is out of scope.
- **Not fresh unless you made it fresh.** Send a nonce.
- Receipts carry no requester identity: shareable without deanonymizing.

## 10. Third-party profile

A provider implements the standard by satisfying §§2.1–2.2, 3, 4, 6 with its
own `iss` and key. The attestation chain (§7–§8 steps 2–4) is the
TrustedRouter profile; third parties MAY substitute their own key-discovery
document at `GET <iss>/.well-known/inference-receipt-keys` (append-only
`{kid, jwk, att?, att_kind?, not_before, not_after, revoked}`), and
conformance requires only that the advertised key verifies the receipts. TEE
evidence upgrades a listing from self-declared to hardware-anchored.
