# Linear-time caller-value equality verification

Changes are confined to `internal/speculation/`; the package remains pure and
unwired. Changes are uncommitted; no git writes were performed. This record
covers the Go port in `spec-e2`. The separate Python checkout is outside this
session's writable roots and was not edited. Its normative document was
re-read after the parallel reference update: the JSON-tree sentence matches
the Go README exactly.

## Comparator and domain

`json.go:245` implements a single iterative lockstep walk with one container
identity set per input. Repetition in either input returns false, rejecting
cycles and shared DAGs. Map membership/lookup makes equality independent of
member order without sorting. Each container's outgoing edges are traversed
at most once before termination: O(size of both inputs) time and space. There
is no recursion, depth limit, or comparison-specific error. Integers, floats
and booleans remain distinct (`int` and `int64` represent JSON integers).

The README mirrors the normative JSON-tree restriction verbatim. Go maps have
pointer identity; slices use backing pointer plus length, preserving distinct
views. `unsafe.Pointer` retains referenced storage. Go cannot distinguish
independent zero-capacity slices by backing pointer (including decoded empty
arrays), or give nil maps unique identity. These represent empty values;
allocated empty maps and slices with backing storage are checked for sharing.

## Frozen literals and tests

All **442 protocol cases + 24 verdict vectors = 466 frozen literals** pass.
All six fixture JSON files remain byte-identical to the Python reference.
Manifest SHA-256:
`ef6cca49eecdea14f47e4419bc1e1543409a22cf715c6cbe1555c8a82701f603`.
No wire, fixture, or frozen expectation changes were made.

Graph tests use in-memory values. Initial isolated comparison timings (excluding
construction; equality tests completed in 0.668 s):

| Case | Result | Comparison time |
|---|---|---:|
| Ring 800 vs 800 | false | 0.108 ms |
| Ring 800 vs 801 | false | 0.284 ms |
| Review cross(10), both directions | false | 0.012 / 0.007 ms |
| Depth-30 shared slices/maps through acceptance | authorization | 0.032 / 0.029 ms |
| 10,000-deep mixed tree, equal/unequal | true/false | 1.84 / 2.34 ms |
| 100,000-deep mixed tree, equal/unequal | true/false | 25.45 / 26.07 ms |
| 100,000-node wide tree, equal/unequal | true/false | 1.42 / 6.65 ms |
| 1,000,000-node wide tree, equal/unequal | true/false | 68.02 / 63.70 ms |
| Wide object with 100,000 container children | true | 40.98 ms |

The wide array counts its root plus scalar leaves as nodes. The wide-object test
also exercises the identity sets at scale. The deep test alternates objects and
arrays. Timings include scheduler and GC variation; the algorithm's work bound
comes from visiting each input container once, not a timing-ratio assertion.

Tests also cover equal trees built in opposite member order (100 repeats),
left-only/right-only sharing, sharing across the two separate inputs, allocated
empty-container sharing, decoded-style empty values, slice views, and scalar
type mismatches. Rings, cross and shared DAGs have one-second bounds; large trees
have ten-second bounds. The 17 original review inputs plus combined mismatches
still run 1,000 times each with deterministic public refusal codes.

## Mutations on temporary copies

The executable inventory was re-anchored to the new comparator. Obsolete
active/completed-pair edits were replaced by per-input identity-set, sharing,
empty-container and member-order edits. The inventory still covers all 259 frozen router rules. The runner executes all equality regression groups and imposes a
45-second process test timeout in addition to comparison-level bounds.

[Full 263-row report](mutation-report.md): **252 red, 11 survived, 0 build-broken**.
All reds killed their selected test. An audit of the JSON event logs confirms
that every mutant ran all 466 literal subtests, fixture pins, and every equality
regression group. The survivor names match the prior report exactly.

The three requested mutations were red:

- Identity-set insertion removed: `TestEqualRings/800_vs_801` failed its
  one-second comparison bound (the 800/800 ring failed too).
- Member-order-dependent comparison: `TestEqualMemberOrder` failed immediately.
- Boolean/integer confusion: `TestLiterals/response_nested_bool_int` incorrectly
  returned `accepted` instead of `authorization` and failed.

The runner intentionally exits 1 for surviving equivalents. No survivor was
removed, reclassified as a kill, or hidden. The 11 equivalents remain:

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

Mutation console log: `/tmp/speculation-linear-mutations.log`.
Detailed output: `/tmp/speculation-linear-mutation-results.json`.
Independent audit: `/tmp/speculation-linear-mutation-audit.log`.

## Environment, coverage, race and fuzz

All Go commands used `GOTOOLCHAIN=go1.24.13`, `GOFLAGS=-mod=mod`, and PATH starting
with `/Users/jperla/josh/repos/tr/quill-router/.venv/bin`.
Writable caches: `GOCACHE=/tmp/speculation-go-cache` and
`GOLANGCI_LINT_CACHE=/tmp/speculation-r2-lint-cache`.

```text
go test -count=1 -coverprofile=/tmp/speculation-linear-cover.out ./internal/speculation
PASS: 7.794 seconds; 99.3% statements (required >=95%); equal/equalScalar 100%.

go test -race -count=1 ./internal/speculation/
PASS: 23.957 seconds on the final test helper; initial concurrent run 53.367 s.

go test -run='^$' -fuzz=FuzzTokens -fuzztime=60s -parallel=4 ./internal/speculation/
PASS: 61.529 seconds; 37,779 executions; 4 new interesting inputs; corpus 950.
```

Logs: `/tmp/speculation-linear-coverage.log`, `/tmp/speculation-linear-race-final.log`,
and `/tmp/speculation-linear-fuzz.log`.

## CI-exact gates

For all five shipped tag sets, with the environment above:

```sh
go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run --allow-serial-runners --build-tags "$tags"
go vet -tags "$tags" ./...
go test -count=1 -tags "$tags" ./...
```

Final gate lines (logs in `/tmp/speculation-linear-gates/`):

```text
cloud_aws,llm_bedrock lint: exit 0 (6.3s)
cloud_aws,llm_bedrock vet: exit 0 (2.1s)
cloud_aws,llm_bedrock test: exit 0 (29.2s)
cloud_aws,llm_multi lint: exit 0 (2.5s)
cloud_aws,llm_multi vet: exit 0 (1.5s)
cloud_aws,llm_multi test: exit 0 (23.8s)
cloud_gcp,llm_vertex lint: exit 0 (2.1s)
cloud_gcp,llm_vertex vet: exit 0 (0.9s)
cloud_gcp,llm_vertex test: exit 0 (23.1s)
cloud_gcp,llm_multi lint: exit 0 (1.7s)
cloud_gcp,llm_multi vet: exit 0 (1.0s)
cloud_gcp,llm_multi test: exit 0 (24.6s)
cloud_azure,llm_multi lint: exit 0 (2.2s)
cloud_azure,llm_multi vet: exit 0 (1.0s)
cloud_azure,llm_multi test: exit 0 (23.4s)
```

The actual workflow's build and race-test steps also passed for all five tags:
`go build -tags "$tags" ./...` and
`go test -race -count=1 -tags "$tags" ./...`.

```text
cloud_aws,llm_bedrock build: exit 0 (1.6s)
cloud_aws,llm_bedrock race-test: exit 0 (118.7s)
cloud_aws,llm_multi build: exit 0 (1.1s)
cloud_aws,llm_multi race-test: exit 0 (86.4s)
cloud_gcp,llm_vertex build: exit 0 (1.1s)
cloud_gcp,llm_vertex race-test: exit 0 (40.1s)
cloud_gcp,llm_multi build: exit 0 (1.2s)
cloud_gcp,llm_multi race-test: exit 0 (46.1s)
cloud_azure,llm_multi build: exit 0 (1.2s)
cloud_azure,llm_multi race-test: exit 0 (75.4s)
```

`gofmt -l internal/speculation`: clean. `git diff --check`: clean.
`TestNoProductionImports`: PASS in the complete package tests. No production
callers or operational behavior were introduced.
