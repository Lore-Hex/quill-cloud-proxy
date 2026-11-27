# Verifying an Azure regional build

For new releases the protected rollout signs a separate record for each region,
in `trust-page/trust/azure-builds/<hostdata>.json` with a sibling `.json.bundle`.
The separate trust publisher verifies the rollout identity and compares all four
fields with the region in `azure-release.json` before signing the public list.
Run `python3 tools/azure_build_witness.py verify` from this repository with
Cosign installed. The two pre-witness tuples are reported as operator assertions.

The witness binds the checked-out commit, the built image digest, the regional
origin and the SHA-256 of the policy in the deployed template. It is a signed
statement from the build and rollout workflow, not an independent rebuild, proof
of current deployment, or proof of GPU attestation. Check a fresh MAA report
from the regional origin against the expected issuer and hostdata separately.
Neither the ARM template nor its environment is published by this mechanism.
