# Isolated KMS denial probe

This is not a serving image, bootstrap client, or accepted measurement. It has
no Secrets Manager client, credentials, production configuration, inference
listener, or secret decryption code. Never add its PCR0 to public or KMS
admission. Never substitute a production enclave in debug mode for this probe.

Build the Dockerfile from the `enclave-go` context and convert the image with
the reviewed, digest-pinned Nitro builder. Record the resulting EIF hash and
nonzero PCR0 before upload. Run it only on a task-owned isolated host, outside
all serving groups, with a distinct CID and enclave name. Do not terminate or
debug any production enclave. The test image exits after one response or at
the 90-second hard deadline.

A parent connects to the probe's vsock port 19102 and writes a fresh 32-byte
challenge. The response is a four-byte big-endian length followed by at most
32 KiB of JSON containing only public attestation evidence, the ephemeral RSA
public key, challenge, and protocol. The private key never leaves the enclave
and is not used to decrypt anything.

Before using a document in a KMS denial test, independently verify the Nitro
certificate chain and COSE signature, freshness, expected EC2 module ID,
challenge, RSA public key, and protocol. A normal run must have the recorded
unpublished PCR0; a separate debug run must have zero PCRs. Neither may match
an accepted measurement. Use only a fresh non-customer test ciphertext with
the approved bootstrap encryption context. An authorization denial counts as
the expected result; malformed-document, invalid-ciphertext, network, or
timeout errors do not. A returned plaintext or recipient ciphertext fails the
gate immediately. Never print such material into logs.

Use the instance role, not the operator, for the negative calls. Leave the
published-image positive test to the real bootstrap flow. Record API request
IDs and failure codes, then remove only the task-owned probe resources.
