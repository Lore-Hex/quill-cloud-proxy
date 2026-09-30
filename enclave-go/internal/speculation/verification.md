# PR 2a round 2 verification record

Changes are confined to `internal/speculation/`; the package remains pure and
unwired. No git writes were performed. HEAD remains `207d9856`; round 2 changes
are uncommitted.

## Fixture and reference parity

All six fixture JSON files were re-copied from
`/Users/jperla/josh/repos/tr/wt/spec-r1/tests/fixtures/speculation_v1/` and verified
with `cmp`. The hard-coded manifest SHA-256 is:

`ef6cca49eecdea14f47e4419bc1e1543409a22cf715c6cbe1555c8a82701f603`

| Category | Matched |
|---|---:|
| grant | 269 |
| descriptor | 37 |
| marker | 52 |
| renewal | 23 |
| replay | 2 |
| cost | 11 |
| allowance | 7 |
| input | 1 |
| verdict_extra | 40 |
| Protocol subtotal | 442 |
| verdict-vectors.json | 24 |
| Total | 466 |

All 466 literals passed in Go and in the updated Python reference, with zero
exclusions or changed expectations. The previous 434 protocol cases are unchanged;
the 24 verdict vectors also remain byte-identical. All manifest-listed hashes
and fixture trailing-newline checks pass.

## Equality regressions

Caller comparison is an iterative boolean operation with no depth cutoff or
refusal of its own. Map key sets are checked before sorted values. Active
container pairs reject cycles; completed pairs are memoized by identity. Slice
identities include length so distinct views of a backing array cannot alias in
the memo. `unsafe.Pointer` identities retain the referenced containers; no pointer
arithmetic or dereferencing is used. Scalar comparisons preserve the documented
JSON types (`int` and `int64` both represent a JSON integer).

The original review files `acceptance-depth-128.json` and `divergences.jsonl`
are copied byte-for-byte into `testdata/review/`, separately from frozen fixtures.
Python independently verified all 17 supplied cases and all 17 variants with a
combined authorization-ID mismatch. `TestReviewAcceptance` checks each outcome
1,000 times: 34,000 acceptance comparisons, with no nondeterministic outcomes.
Cycles now produce the caller's `authorization` refusal rather than `input`.

`TestEqualDeep` checks equal and unequal independently allocated values at depth
10,000. `TestEqualValues` covers types, unsupported values, cycles, distinct slice
views, and completed-pair identity. `TestEqualSharedDAG` checks depth-30 maps and
slices, both shared between arguments and independently allocated. Measured
combined acceptance checks were **0.090 ms for slices and 0.071 ms for maps**;
the test has a one-second timeout to fail exponential regressions promptly.

## Mutation inventory

[Full 263-row report](mutation-report.md): **252 red, 11 survived, 0 build-broken**.
All 252 reds fail their inventory-selected test. The 16 new equality mutations
are all red. The original five equality mutations were re-anchored to the new
implementation. Router-rule references were remapped to the updated frozen
inventory, covering all 259 entries.

The JSON event logs were audited: every one of the 263 mutants ran all 466
literal subtests plus fixture-pin and equality regression tests. The runner's
exit status is intentionally 1 because it reports surviving equivalents.
Detailed output is retained at `$TMPDIR/speculation-mutation-results.json`;
console output is `/tmp/speculation-r2-mutations.log`.

The survivors are exactly the same 11 confirmed equivalents from review:

| Surviving edit | Remaining protection |
|---|---|
| Raw-number length/form guard | JSON grammar and checked `ParseInt` |
| Verified payload object-root guard | Immediate exact schema |
| Final authorization nonce comparison | Earlier descriptor and marker bindings |
| Final authorization workspace comparison | Earlier descriptor binding |
| Final authorization key comparison | Earlier descriptor binding |
| String type predicate | Failed assertion yields rejected empty string |
| Object field-count equality | Required-field membership |
| Compact string predicate | Failed assertion fails two-dot check |
| Permit array predicate | Failed assertion fails nonempty check |
| Context binding presence | Missing nil cannot equal validated signed binding |
| Schema object-root predicate | Nil map fails required field count |

## Fuzz, race and coverage

All Go commands used `GOTOOLCHAIN=go1.24.13`, `GOFLAGS=-mod=mod`, and PATH starting
with `/Users/jperla/josh/repos/tr/quill-router/.venv/bin`. Writable caches were
`GOCACHE=/tmp/speculation-go-cache` and
`GOLANGCI_LINT_CACHE=/tmp/speculation-r2-lint-cache`.

```text
go test -run='^$' -fuzz=FuzzTokens -fuzztime=60s -parallel=4 ./internal/speculation/
PASS: 61.349 seconds; 35,285 executions; 4 new interesting inputs; total corpus 946

go test -race ./internal/speculation/
PASS: 22.538 seconds

go test -count=1 -coverprofile=/tmp/speculation-r2-cover.out ./internal/speculation/
PASS: 99.3% statement coverage (required >=95%)
```

Logs: `/tmp/speculation-r2-fuzz.log`, `/tmp/speculation-r2-race.log`, and
`/tmp/speculation-r2-coverage.log`.

## CI-exact gates

For each of the five shipped tag sets:

```sh
go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run --allow-serial-runners --build-tags "$tags"
go vet -tags "$tags" ./...
go test -count=1 -tags "$tags" ./...
```

Final gate lines (logs in `/tmp/speculation-r2-gates/`):

```text
cloud_aws,llm_bedrock lint: exit 0 (2.1s)
cloud_aws,llm_bedrock vet: exit 0 (1.2s)
cloud_aws,llm_bedrock test: exit 0 (21.6s)
cloud_aws,llm_multi lint: exit 0 (18.0s)
cloud_aws,llm_multi vet: exit 0 (1.4s)
cloud_aws,llm_multi test: exit 0 (21.5s)
cloud_gcp,llm_vertex lint: exit 0 (4.1s)
cloud_gcp,llm_vertex vet: exit 0 (0.6s)
cloud_gcp,llm_vertex test: exit 0 (22.5s)
cloud_gcp,llm_multi lint: exit 0 (8.8s)
cloud_gcp,llm_multi vet: exit 0 (0.6s)
cloud_gcp,llm_multi test: exit 0 (21.6s)
cloud_azure,llm_multi lint: exit 0 (10.7s)
cloud_azure,llm_multi vet: exit 0 (1.1s)
cloud_azure,llm_multi test: exit 0 (23.2s)
```

`gofmt -l internal/speculation`: clean. `git diff --check`: clean.
`TestNoProductionImports`: PASS. No production callers or operational behavior
were introduced.
