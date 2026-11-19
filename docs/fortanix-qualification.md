# Fortanix GLM-5.3-Flash: verifier qualification

This is an operator-only preflight. Neither mode makes an inference request,
changes routing, enables a fallback, or grants a Confidential label. The normal
managed ZDR client is unchanged. A successful CPU check is **not** a signed
GPU or switch verdict. A full hardware check is **not** a weight-integrity
sign-off.

The candidate reference comes from [Fortanix's published release](https://github.com/fortanix/armet-ctf/tree/5ba767a9553173bb4fc3977a979f8e7cbc0e36b8).
MRTD and all four RTMRs must match that reference. MRCONFIGID must match its
initdata SHA-384. Do not update a reference from a live response. Policy and
weight-manifest review is separate from verifying that the endpoint runs that
configuration.

From the repository root, in an operator environment with the managed
`FORTANIX_API_KEY` already set (never pass it as a command-line argument):

```sh
proofdir=$(mktemp -d)
(cd enclave-go/sidecar && go test -c -tags cloud_gcp -o "$proofdir/verifier.test")
(cd enclave-go && FORTANIX_QUALIFICATION=cpu \
  FORTANIX_QUALIFICATION_BINARY="$proofdir/verifier.test" \
  go test -tags cloud_gcp,llm_multi -count=1 -run '^TestFortanixQualificationLive$' ./internal/llm)
```

The live test makes one authenticated HTTP/1.1 report GET over verified TLS.
It generates its own random challenge, hashes the peer certificate's public
key, and passes those observations and the report privately to the local
verifier. It does not write evidence to disk. The verifier checks Intel TDX
collateral and revocations, production mode, the candidate measurements,
and the signed binding to the native model and exact NVIDIA payload.

Only with permission to disclose the devices' evidence and certificates to
NVIDIA, explicitly substitute `devices` for `cpu`. This requests one
[GPU](https://docs.api.nvidia.com/attestation/reference/attestmultigpu) and
one [switch](https://docs.api.nvidia.com/attestation/reference/attestswitch)
appraisal (stop on failure). No Fortanix key or user traffic goes to NVIDIA.
The verifier checks the signed overall and detached device tokens, issuer,
expiry, freshness, nonce, bound digests, secure boot, debug state, certificate
and firmware checks, unique devices, and consistent signed 8-GPU/4-switch
[topology](https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/ppcie-verifier-sdk-cpp/ppcie/verifier/src/topology/validate_topology.py).
Keep raw evidence and certificates out of commits, issue trackers, and logs.

Production enablement is separate: review the trust reference and runtime
weight-integrity evidence, qualify a fresh full hardware proof, integrate the
enclave's verifier connection and cloud egress path, run guarded canaries, and
verify customer traffic cannot take the ordinary ZDR client when Confidential
is required. Do not advertise Confidential before all of these pass.
