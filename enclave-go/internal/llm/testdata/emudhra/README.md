# eMudhra TLS rejection fixtures

Public certificates only. No private keys or exploit code.

Source: https://emudhra.we-have-a-problem.com/chains.zip and
https://emudhra.we-have-a-problem.com/roots.json, retrieved 2026-10-20.
Upstream incident: https://bugzilla.mozilla.org/show_bug.cgi?id=2083449.
Go fix: https://go.dev/issue/82345 (Go 1.26.10 / 1.27.3).

The twelve chains cover the six TLS intermediate keys, both their emSign
and AAA Certificate Services cross-signed paths. The test deliberately
trusts the historical roots so it exercises Go's compromised-key block,
not just an updated OS bundle. Time is frozen inside certificate validity,
and fixture signatures and hostnames are checked before the rejection test.
