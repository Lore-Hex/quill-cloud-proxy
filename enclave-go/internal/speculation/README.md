# Speculation protocol v1 (PR 2a)

Pure, unwired Go port of router `speculation_protocol.py`. No dispatch, output,
billing, storage, flags, request exclusions, local eligibility snapshot, or
monotonic-clock integration is added here. Those are later integration work.
The normative contract is router `docs/speculation-protocol-v1.md`.

`VerifyGrant`, `VerifyDescriptor`, `VerifyAcceptance`, `RenewalVerdict`,
`DescriptorReplay`, `CostCeiling`, `WorkspaceAllowance`, `ClassifyVerdict`, and
`SHA256` mirror the Python operations. Failures return `ProtocolError`, whose
string is the frozen refusal code. `TrustedKey` and all current binding inputs
come from the caller's authenticated local state. No token supplies trust.

JSON-domain caller objects use `map[string]any` and `[]any`. Integers use `int64`
or `int`; floats and booleans remain distinct. The public-key encoding is `any`
so malformed configuration gets the protocol's `signature` refusal. Other Go
struct/string parameters prevent invalid caller shapes statically. Verified
objects have private immutable payloads; `Claims()` returns an independent copy.
A zero-valued verified object confers no authority.

Caller-value comparisons are pure boolean, type-sensitive, depth-unbounded and
independent of member order; they never produce their own error code. An explicit
stack checks map key sets before sorted values, detects active container cycles
and memoizes completed container pairs by identity. Cycles and unsupported values
compare unequal; callers retain their existing refusal codes. Shared acyclic
subtrees are visited once per pair, including independently allocated graphs.

Wire JSON first enforces printable ASCII without backslashes and a maximum
container depth of 16. A `json.Decoder.Token` / `UseNumber` pass records duplicate
names and raw numbers without semantic refusal until the whole syntax is valid.
A small lexical adapter recognizes the three Python JSON constants without
converting them to floats. Duplicates then precede bounded numeric validation.
Exact schema validation precedes canonical encoding. On this validated alphabet,
`json.Marshal` gives sorted, compact, escape-free bytes without a newline.

Ed25519 checks key and signature lengths explicitly. Base64url has an alphabet
precheck plus strict decoding and re-encoding; CR/LF and padding are refused.
Permit sums cannot overflow: compact tokens are limited to 65,536 characters
and every permit is checked against a ceiling at most 10,000 before summing.
Internal protocol refusals unwind the ordered checks and are recovered at API
boundaries. Unexpected implementation panics are not hidden from tests/fuzzing.

## Frozen evidence

The six JSON files in `testdata/speculation_v1` were copied byte for byte, never
regenerated. `TestFixturePins` pins the manifest SHA-256 and checks every listed
file hash. The actual pinned bundle contains **442 protocol cases + 24 verdict
vectors = 466 total**. Every case runs, with no exclusions or changed expectations.

Run from `enclave-go`:

```sh
go test -count=1 -cover ./internal/speculation
go test -race ./internal/speculation
go test -run='^$' -fuzz=FuzzTokens -fuzztime=60s ./internal/speculation
```

The fuzz corpus includes all protocol literals, their compact tokens, and their
decoded header/payload bytes. Fuzzing also signs arbitrary payload bytes with the
public test-only fixture seed, reaching validation beyond signature verification.
Fixtures and signing seeds must never enter production trust configuration.

## Mutation testing

From this package directory:

```sh
go run ./testdata/mutate.go
```

`mutations.json` maps executable Go edits to zero-based entries in the frozen
router `rules.json`. The Go runner first checks a clean baseline, then copies
source and fixtures to independent temporary modules. Every mutant runs every
protocol literal, every verdict vector, the fixture-pin test, and equality
regressions. No git operation is used. It writes `mutation-report.md`; detailed stdout is retained in
`$TMPDIR/speculation-mutation-results.json`. Compile failures are `build-broken`,
never red. The report distinguishes corpus failures from the selected literal's
failure. Any survival, build failure, or un-killed selected literal makes the
runner exit nonzero so evidence cannot silently appear all-green.

Some defensive checks overlap: Go's checked integer conversion independently
rejects values over 19 digits; later schemas independently require object roots;
and acceptance's initial ordinary-authorization checks overlap its final marker
comparison. Mutating only one overlapping check can survive without permitting a
new behavior. These survivors are retained and reported, not removed or counted
as successful kills. See the full [mutation table](mutation-report.md) and
[verification record](verification.md).
