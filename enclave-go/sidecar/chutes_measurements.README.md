# Chutes TEE measurement snapshot

`chutes_measurements.json` is the release-pinned snapshot fetched from
`https://api.chutes.ai/servers/tee/measurements` on 2026-08-15.

SHA-256: `8b4fec0e6b0e5d133c5354fd88d4ea9a338f9fca13b3d8ec2a61925f3007b704`

The verifier accepts only an exact MRTD and runtime RTMR0 through RTMR3 match
from this file. A Chutes measurement change therefore fails closed until the
new public snapshot is reviewed, tested, committed, and deployed in a newly
attested TrustedRouter image.
