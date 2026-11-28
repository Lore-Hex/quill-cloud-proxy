# Azure raw hardware evidence

`GET /attestation?format=amd-snp-v1&nonce=<64 hex digits>` requests a
1,184-byte AMD SEV-SNP report. It is opt-in; the original attestation endpoint
continues to serve MAA tokens. Unsupported formats and clouds return an error.
There is no JWT fallback. The report is never cached or attached to customer
requests. Only one raw sidecar call at a time is allowed per enclave.

For each TLS 1.3 session, choose a new random 32-byte challenge. Let `leaf`
be the DER of the peer leaf certificate and `exporter` be the 32-byte TLS
exporter with label `EXPORTER-Channel-Binding` and no context. The binary
preimage sent to the local Microsoft SKR 2.7 sidecar is:

    ASCII("trustedrouter/azure-snp/session/v1") || 0x00 ||
    SHA256(leaf) || challenge || exporter

The AMD-signed REPORT_DATA must be exactly SHA256(preimage) followed by
32 zero bytes. The verifier must obtain the certificate and exporter from the
same live TLS connection it will use for inference. Do not follow redirects,
accept a JWT here, trust a measurement supplied by the endpoint being checked,
or send a prompt or credential before verification succeeds.

Check the signature and endorsements to AMD's pinned product root, revocation
status, a non-debug guest policy, VM privilege level, independently accepted
guest launch measurement, regional CCE policy (HOST_DATA) and minimum TCB
versions as well as REPORT_DATA. Use fresh, reviewed AMD firmware baselines
appropriate to the processor and independently authenticated workload pins.
Parsing the report is not verification. Failure to obtain AMD endorsements or
any policy mismatch is a verification failure. This concerns the CPU gateway,
not an upstream model or GPU.

The wire format comes from [Microsoft's SKR 2.7
source](https://github.com/microsoft/confidential-sidecar-containers/blob/21db190e21551448f6020722e74be3dd42fa02f6/cmd/skr/README.md).
Test both regional origins against independently approved releases before
treating the raw endpoint as live.
