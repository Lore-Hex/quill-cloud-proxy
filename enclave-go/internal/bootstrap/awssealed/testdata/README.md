# Public KMS interoperability fixture

`upstream-kms.json` contains the already-public recipient private key, ciphertext
and expected key from EdgeBit's Nitro SDK test at commit
`8a5476ff3cc2157309873160fd658654c6aa2d87`. The upstream test identifies the bytes as
`CiphertextForRecipient`. These are test vectors, not TrustedRouter credentials.
No upstream parser implementation is used. Both upstream license notices are
retained here. The only transformation is Go literals to JSON and hexadecimal.

This fixture checks compatibility with a published KMS response. It does not
replace a current, isolated production-candidate KMS round trip before activation.
