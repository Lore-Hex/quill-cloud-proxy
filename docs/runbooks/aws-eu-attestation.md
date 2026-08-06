# AWS EU attested gateway — runbook

`api-aws.trustedrouter.com` is the attested Nitro Enclave gateway for the
standalone EU deployment. It is a peer of `api.trustedrouter.com` (GCP
Confidential Space), not a failover of it: separate database, separate
credits, separate TLS identity.

| name | serves | where |
| --- | --- | --- |
| `api-aws.trustedrouter.com` | attested gateway (Nitro) | NLB → eu-west-1 ASG |
| `aws.trustedrouter.com` | EU control plane / status page | App Runner `tr-eu`, eu-west-3 |
| `api.trustedrouter.com` | attested gateway (GCP) | GCP Confidential Space |

Do not point the gateway name at the control plane or vice versa. The
enclave's self-signed cert carries `QUILL_API_HOST` as its only SAN, so a
mismatch surfaces as a hostname error even though attestation is healthy.

## Verifying it

```bash
uv run tools/verify-attestation.py \
  --api-host api-aws.trustedrouter.com --port 443 --samples 2 \
  --attested-cert-only \
  --expected-pcr0 <pcr0 from the trust page>
```

`--attested-cert-only` is REQUIRED here and is not a weakening. The enclave
mints a self-signed cert inside the TEE; trust comes from the attestation
document binding that cert's fingerprint, not from a CA. The flag skips CA
chain validation only — the cert-to-attestation binding check still runs
unconditionally, so a substituted cert fails even though the handshake
succeeded.

A full pass prints, per sample:

```
[ok] COSE_Sign1 chain validates to AWS Nitro root
[ok] PCR0 matches ...
[ok] live cert SPKI matches AWS attestation
[ok] user_data cert fingerprint matches
[ok] TLS exporter channel binding bound in AWS user_data
[ok] follow-up /attestation stayed on the attested TLS socket
```

## The failure mode that cost the most time

`/attestation` returned nothing for an extended period while **every**
health signal was green. Read this before debugging a silent enclave.

The chain, from symptom down to cause:

1. `curl https://<nlb>/attestation` → `http=000`.
2. NLB target group says **healthy** — it is a *TCP* check, so it passes
   through a dead enclave. Ignore it as evidence.
3. `nitro-cli describe-enclaves` shows `RUNNING`, then the enclave
   disappears and the supervisor restarts it. Restart counts climb.
4. Parent `/health` returns **200** the whole time, because uvicorn is up
   and /health does not depend on the bootstrap task.
5. Enclave console (debug EIF) shows the real error:
   `bootstrap fetch failed: dial vsock vm(3):9100: connect: connection reset by peer`
6. Nothing is bound on vsock 9100. `ss -l -A vsock | grep 9100` on the
   parent confirms it.
7. `docker logs quill-parent | grep bootstrap` shows `bootstrap.refresh_failed`
   in a loop — the payload never built, so `listener.bind()` was never
   reached.

Root cause: `_unwrap_gcp_sa_key` raised on an absent cross-cloud GCP SA
key, `refresh()` swallowed the exception, and the "wait for first payload"
loop spun forever. The standalone EU region holds no GCP credential by
design, so the key is absent permanently.

Fixed in `bootstrap_server.py`: the SA key is optional (absent → warn and
continue; present-but-undecryptable → still raise), and the first-payload
wait now warns every 15s naming both the symptom and the consequence.

**The transferable lesson:** every green signal in that list was a *proxy*
for enclave health, and each one stayed green through a total outage. Only
the enclave's own console and the vsock listen table were the thing
itself. When a component is silent, go to its own output before trusting
anything that merely observes it.

Debug-mode consoles are also destructive on a live host:
`nitro-cli run-enclave --debug-mode` terminates the running enclave and
collides on CID 16. Stop the supervisor first, and never read a console on
a host whose restart count you are simultaneously using as evidence.

## Inference path (enclave → control plane)

`/attestation` working does NOT mean inference works — they fail
independently. Attestation is self-contained inside the enclave; inference
needs the enclave to authorize the caller's key against a control plane
over vsock.

The authorize call goes to `POST {control_plane}/v1/internal/gateway/authorize`
with header `x-trustedrouter-internal-token`, tunneled via **vsock port
8040**. The token comes from Secrets Manager
`quill/trustedrouter-internal-gateway-token` (same value Cloud Run consumes
as `TR_INTERNAL_GATEWAY_TOKEN` — compare sha256 fingerprints, never values).

Getting this working produced a ladder of *different* errors. Each one is a
distinct cause, so read the code before assuming:

| Response | Meaning |
| --- | --- |
| `401 Invalid API key` | the enclave could not authorize AT ALL — usually the internal token is missing from this region's Secrets Manager |
| `404 route not found` | auth SUCCEEDED; that path is not a gateway route. `GET /v1/models` is the public catalog exception and should return `200` without auth. |
| `502 gateway authorization failed` after ~28s | the authorize call TIMED OUT. 28s is retries, not rejection — a rejection is fast |
| `400 Model does not support chat completions: auto` | full path works; use a catalog id such as `trustedrouter/auto` |
| `200` | done |

**Isolating a 502 timeout.** Run the authorize call from the PARENT host
(which has ordinary network) with the token from Secrets Manager. If the
parent gets a fast answer (a `400 model: Field required` on an empty body
is a healthy response — the token was accepted) while the enclave times
out, the fault is strictly the enclave→vsock→parent hop, not auth and not
the control plane. That single differential test replaces a lot of guessing.

In the one occurrence so far, `systemctl restart quill-vsock-proxy-8040`
fixed it immediately. The likeliest mechanism is that `vsock-proxy` pins the
address it resolved at startup while `trustedrouter.com` sits behind a load
balancer whose IP can change — but a wedged proxy process fits the same
evidence, so treat the mechanism as UNCONFIRMED. Do not add a blind
periodic restart: recycling the tunnel kills in-flight streaming requests.
Detect it with a synthetic that exercises a real completion end to end.

## Traps

- **`--phase compute` used to scale the ASG to zero.** `ASG_DESIRED`
  defaults to 0. Updating an existing ASG now preserves running capacity
  unless `ASG_DESIRED` is set explicitly, but if you see an empty ASG after
  a deploy, check the scaling activity's `Cause` field first.
- **NLB IPs change on instance replacement.** Any script that caches an IP
  for verification will report a false failure after a roll. Resolve fresh,
  or use the hostname.
- **`TR_API_BASE_URL` defaults to GCP prod.** Unset on a new service means
  probes silently record the wrong cloud's health.
