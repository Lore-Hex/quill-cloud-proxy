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
