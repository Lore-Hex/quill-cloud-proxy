# Frozen billing v1

This package implements the router's frozen billing snapshot v1 contract. It is
not imported by any request path. `trustedrouter.Authorization` only stores the
optional response metadata; settlement remains synchronous for every mode.

## API

- `ParseSnapshot` strictly validates JSON and creates an immutable `Snapshot`.
  `Candidates` returns a deep copy, including tiers and boundary pointers.
- `ParseRawUsage`, `ParseEligibility`, `ParseEnvelope`, and `ParseAcceptance`
  validate the corresponding wire records. Unknown fields, duplicate keys,
  coercible integers, and unsupported literals are errors. All parse entry points
  require BOM-free UTF-8, reject raw NUL bytes as `invalid_encoding`, and reject
  lone surrogate escapes in values or keys at any depth as `invalid_string`.
  Valid surrogate pairs and escaped NUL remain accepted.
- `DefaultEligibility` supplies ordinary typed local Credits facts.
  `RequireEligible` rejects the first unsupported feature in contract order.
  Callers must populate both requested and observed facts; the package cannot
  discover feature usage or authenticate an authorization.
- `Evaluate` uses the selected frozen candidate and checked signed-int64
  arithmetic. It normalizes cache counts once, rounds each component half-up,
  uses inclusive context tiers with last-tier fallback, and never clamps a
  charge to an estimate. Reasoning is informational within output.
- `CanonicalBytes` and `CanonicalHash` emit the Python-compatible ASCII JSON
  and lowercase SHA-256. Defaults and nulls are included; keys are sorted.
  DEL and C0 controls use the exact Python `ensure_ascii=True` escape forms.
- `ValidateEnvelope` binds the hash, selected endpoint, normalized usage, and
  exact charge. It does not verify a ticket or persisted authorization identity.
  Accepted and duplicate outcomes acknowledge pending responsibility only.
- `ParseEndpoint` and `BuildSnapshot` freeze effective endpoint prices without
  catalog access. Cache prices are resolved at construction, with explicit zero
  preserved. Endpoint cache multipliers use the reference's half-even rounding;
  usage charges use per-component half-up rounding.

`Error` exposes a stable `Code`, plus `Field` and `Kind` details. Parse failures
use `invalid_encoding` or `invalid_string` for wire encoding/string errors,
otherwise `invalid_snapshot`, `invalid_usage`, `invalid_context`, `invalid_envelope`,
`invalid_acceptance`, or `invalid_builder`; evaluation failures use exact
semantic or exclusion codes such as `arithmetic_overflow`, `malformed_usage`,
and `unsupported_endpoint`. A `string_type` detail remains distinguishable from
its enclosing model class. Directly constructed Go usage, eligibility, and
envelopes are validated too. A zero-value `Snapshot` is invalid.

## Shared fixture gate

The existing files in `../trustedrouter/testdata/async_settlement` are consumed
unchanged. `TestFixturePin` pins `billing_v1.json` to
`4aedf13e4ba30b4d1f0767f829e790c37ce3f957a39c15d1eb6aff8c8734fd81`.
`TestFixtures/<case name>` runs every literal case:

| Kind | Cases | Go execution |
| --- | ---: | --- |
| evaluation (no operation) | 146 | Parse, eligibility/build or evaluate; compare literal usage, charge, envelope hash, and canonical round trip |
| snapshot_json | 22 | `ParseSnapshot` on literal JSON text or `raw_json_hex` bytes |
| eligibility_json | 14 | `ParseEligibility`; exact wire errors, canonical bytes, and hashes |
| envelope_json, acceptance_json, model_json | 6 | Corresponding production parser; exact wire errors |
| model | 267 | The production model validator, including nested semantic checks |
| field | 208 | The production field validator with that field's actual type and tags |
| type | 41 | The production primitive validator |
| builder | 25 | Raw endpoint conversion matching Python, then `ParseEndpoint` and `BuildSnapshot` |
| envelope | 6 | `ParseEnvelope` and `ValidateEnvelope`; one explicit evaluator-boundary fault |
| acceptance | 20 | The production acceptance validator |
| checked | 4 | Signed-int64 domain check and checked addition |
| **Total** | **759** | Literal expectations; no generated oracle |

The rules-manifest subtest requires every rejection and positive case referenced
by each of the supplied manifest's **374 rules** to execute successfully. Field-only cases intentionally omit enclosing model validators,
matching Python's `TypeAdapter(field.rebuild_annotation())` semantics.

Go-only tests cover detached snapshot/candidate/tier data, builder copies and
sorting, concurrent evaluation and hashing, malformed JSON, arithmetic edges,
ASCII serialization, and validation of directly constructed Go values. Encoding
regressions reproduce the reviewed DEL, lone-surrogate, and BOM differences,
check all C0 escape forms, and exercise every public parser. The harness preserves
raw bytes and represents Python literal lone surrogates as equivalent JSON escapes
before passing them to the production decoder.
