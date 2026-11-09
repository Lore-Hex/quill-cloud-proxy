# Frozen billing v1

This package implements the router's frozen billing snapshot v1 contract. It is
not imported by any request path. `trustedrouter.Authorization` only stores the
optional response metadata; settlement remains synchronous for every mode.

## API

- `ParseSnapshot` strictly validates JSON and creates an immutable `Snapshot`.
  `Candidates` returns a deep copy, including tiers and boundary pointers.
- A candidate's `provider` is any provider slug in the identity alphabet
  (`^[A-Za-z0-9_./:@+\-]+$`, 1 to 512 characters), not a fixed list, and
  `model_id` is not tied to it: a provider serving another publisher's model is
  accepted. Its `prompt_convention` must be what `PromptConvention` gives:
  `excludes_cache` when the provider is exactly `anthropic`, or when it is
  `amazon-bedrock` or `google-vertex` and the model identifier begins with
  `anthropic/` (the enclave relays those streams in Anthropic's own format, so
  their input count leaves out cached tokens; `internal/llm`'s
  `TestBillingConventionFollowsNativeAnthropicRelays` ties the rule to that
  dispatch); `includes_cache` for every other candidate, including those two
  providers' other models. The router's settle path applies the same rule.
  Other native relays are outside it: `azure` sends a `claude-` model through
  its Anthropic wire client (`internal/llm/azure.go`), `zero-g` does the same
  for a `claude-` upstream id or an `anthropic/` model (`internal/llm/zero_g.go`),
  and the legacy `vertex` slug reaches the native Vertex client; the catalog
  has no such Credits endpoint, and the router's
  `tests/test_resold_claude_cache_accounting.py` fails if one appears, which is
  when the rule must grow on both sides. At settlement the enclave also
  requires the stream's own convention (the adapter's `InputExcludesCache`) to
  agree with the selected candidate's, or it settles synchronously. One refused
  candidate refuses the whole snapshot.
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
  usage charges use per-component half-up rounding. Only this package's tests
  call them: the router builds every snapshot, and no run-time path here builds
  one. The router resolves default cache prices from its own pricing table. To
  avoid a copy of that table that could drift unseen, `BuildSnapshot` holds a
  cache price rule only for the providers whose frozen rates a literal
  expectation pins (`openai` 2, `anthropic` 10, `google-vertex` 4 and
  `amazon-bedrock` 1 as prompt-price divisors), and refuses an endpoint of any
  other provider with `invalid_builder`. Add a provider to `cacheReadDivisor`
  only together with a shared fixture case (`freeze_cache_rate`) that drives its
  frozen rates.

`Error` exposes a stable `Code`, plus `Field` and `Kind` details. Parse failures
use `invalid_encoding` or `invalid_string` for wire encoding/string errors,
otherwise `invalid_snapshot`, `invalid_usage`, `invalid_context`, `invalid_envelope`,
`invalid_acceptance`, or `invalid_builder`; evaluation failures use exact
semantic or exclusion codes such as `arithmetic_overflow`, `malformed_usage`,
and `unsupported_endpoint`. A `string_type` detail remains distinguishable from
its enclosing model class. Directly constructed Go usage, eligibility, and
envelopes are validated too. A zero-value `Snapshot` is invalid.

## Shared fixture gate

The files in `../trustedrouter/testdata/async_settlement` are consumed
unchanged. `TestFixturePin` pins the base `billing_v1.json` to
`4aedf13e4ba30b4d1f0767f829e790c37ce3f957a39c15d1eb6aff8c8734fd81` and
`billing_v1.rules.json` to
`ab9bac52a666efb4e268dbec210c1a598e490815bf25501ccc0759fe722ce5c4`, and the
router's every-provider supplement `billing_v1_providers.json` to
`b74f40c3c079569e63bc8d296ca2a9953e9b09b5b2a5b6eb24b1cf85a2df45f4` (its schema
to `de35dba91ae2970afee42f3983de2351264721228ebd8e31a4436b7bf206dc15`). The
supplement names the base hashes, 4 superseded base cases, 4 superseded base
rules, 24 cases and 18 rules. The merged contract is the base minus the
superseded names, in base order, then the supplement in its order: 779 cases
and 388 rules. A superseded name may return from the supplement as a successor
rule; otherwise every merged name is unique. `TestFixtures/<case name>` runs
every merged case:

| Kind | Cases | Go execution |
| --- | ---: | --- |
| evaluation (no operation) | 154 | Parse, eligibility/build or evaluate; compare literal usage, charge, envelope hash, and canonical round trip |
| snapshot_json | 22 | `ParseSnapshot` on literal JSON text or `raw_json_hex` bytes |
| eligibility_json | 14 | `ParseEligibility`; exact wire errors, canonical bytes, and hashes |
| envelope_json, acceptance_json, model_json | 6 | Corresponding production parser; exact wire errors |
| model | 274 | The production model validator, including nested semantic checks |
| field | 211 | The production field validator with that field's actual type and tags |
| type | 41 | The production primitive validator |
| builder | 27 | Raw endpoint conversion matching Python, then `ParseEndpoint` and `BuildSnapshot` |
| envelope | 6 | `ParseEnvelope` and `ValidateEnvelope`; one explicit evaluator-boundary fault |
| acceptance | 20 | The production acceptance validator |
| checked | 4 | Signed-int64 domain check and checked addition |
| **Total** | **779** | Literal expectations; no generated oracle |

The rules-manifest subtest requires every rejection and positive case referenced
by each of the merged manifest's **388 rules** to execute successfully, so a
rule that still names a superseded case fails. Field-only cases intentionally omit enclosing model validators,
matching Python's `TypeAdapter(field.rebuild_annotation())` semantics.

Go-only tests cover detached snapshot/candidate/tier data, builder copies and
sorting, concurrent evaluation and hashing, malformed JSON, arithmetic edges,
ASCII serialization, and validation of directly constructed Go values. Provider
tests (`provider_test.go`) cover a resold model, amazon-bedrock and google-vertex
serving an `anthropic/` model beside amazon-bedrock serving another publisher's,
the provider pattern, the prompt convention rule, a snapshot that mixes
providers, and the builder's refusal of a provider without a cache price rule;
their expected counts, charges and hash are literals. Encoding
regressions reproduce the reviewed DEL, lone-surrogate, and BOM differences,
check all C0 escape forms, and exercise every public parser. The harness preserves
raw bytes and represents Python literal lone surrogates as equivalent JSON escapes
before passing them to the production decoder.
