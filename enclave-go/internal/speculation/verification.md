# PR 2a verification record

Protocol implementation is pure and unwired. Only `internal/speculation/` is new;
no existing production files, flags, or request paths were changed. No git writes
were performed; all changes remain uncommitted.

## Fixture parity

The provided pinned bundle contains **434 protocol cases plus 24 verdict vectors,
458 total**. The requested count of 458 *protocol* cases plus verdict vectors does
not match the files under the required manifest. All actual literals were evaluated;
none were excluded, generated, modified, or given new expectations.

| Category | Matched |
|---|---:|
| grant | 269 |
| descriptor | 37 |
| marker | 44 |
| renewal | 23 |
| replay | 2 |
| cost | 11 |
| allowance | 7 |
| input | 1 |
| verdict_extra | 40 |
| Protocol subtotal | 434 |
| verdict-vectors.json | 24 |
| Total | 458 |

All six JSON files compare byte for byte with the router checkout. The manifest
SHA-256 is pinned in the Go test to
`efcf82227d5edb22f90482e414ad6c54dba293166a9febd1a976e6a3c234769e`.
Every manifest-listed hash and fixture trailing newline passed validation.
No literal/contract divergence was found.

## Mutations

[Full 247-row mutation table](mutation-report.md): **236 red, 11 survived,
0 build-broken**. Every red mutant failed its inventory-selected named literal.
The mutation runner intentionally exits 1 when survivors exist. Every one of the
247 temporary copies ran all 458 named literal subtests and `TestFixturePins`;
this was also checked against the runner's JSON event logs. All 247 frozen router
inventory entries have corresponding Go mutation references.

| Required mutation | Result | Failing test |
|---|---|---|
| dry-run accepted as real | red | TestLiterals/dry_run_cannot_dispatch |
| ignore key epoch | red | TestLiterals/binding_key_epoch |
| ignore boot binding | red | TestLiterals/binding_boot_id |
| ignore route binding | red | TestLiterals/route_endpoint_id |
| all 402 to workspace | red | TestVerdicts/lifetime_limit |
| all 429 to key | red | TestVerdicts/rate_workspace |
| round B down | red | TestLiterals/money_fractional |
| shadow-purpose key for real grant | red | TestLiterals/real_type_shadow_key |
| skip canonical payload | red | TestLiterals/payload_whitespace |
| accept padded base64 | red | TestLiterals/signature_padded |
| accept CR/LF in base64 | red | TestLiterals/base64_cr |
| skip byte rule | red | TestLiterals/trailing_newline |
| semantics before syntax | red | TestLiterals/payload_number_later_syntax |
| duplicate detection disabled | red | TestLiterals/payload_duplicate |
| float accepted as integer | red | TestLiterals/context_coercion_input_rate_micro_per_m |
| wrong-length Ed25519 key panics | red | TestLiterals/key_short_public |
| fixture byte changed | red | TestFixturePins |

Survivors were retained rather than counted as kills:

| Surviving edit | Remaining protection |
|---|---|
| Remove raw-number length/form guard | `strconv.ParseInt` still rejects overflow and fractional/constant syntax. |
| Remove verified payload object-root guard | The next operation's exact schema rejects the non-object root. |
| Skip final authorization nonce comparison | Initial authorization/descriptor comparison and marker/descriptor comparison already bind the nonce. |
| Skip final authorization workspace comparison | Initial authorization/descriptor comparison already binds workspace. |
| Skip final authorization key comparison | Initial authorization/descriptor comparison already binds key. |
| Remove string type predicate | Failed Go type assertion produces empty string, still rejected by the nonempty check. |
| Permit object field count below schema count | The following required-field membership loop rejects every missing field. |
| Remove compact string type predicate | Failed Go assertion produces empty string, still rejected by the two-dot check. |
| Remove permit array type predicate | Failed Go assertion produces nil slice, still rejected by the nonempty check. |
| Remove context binding presence predicate | Missing value is nil, which cannot equal a required signed string or integer. |
| Remove object-root type predicate | Failed Go assertion produces nil map, still rejected by exact field count. |

## Fuzz, race and coverage

`go test -run='^$' -fuzz=FuzzTokens -fuzztime=60s -parallel=4
./internal/speculation/`: PASS, **61.275 seconds, 145,894 executions**, no panic.
The seed corpus includes every protocol case, token bytes and decoded segments;
arbitrary payload bytes are also signed to reach post-signature parsing.

`go test -race ./internal/speculation/`: PASS, including concurrent access to
independent claims copies and replay checks.

`go test -count=1 -coverprofile=/tmp/speculation-cover.out
./internal/speculation`: PASS, **98.5% statement coverage** (required ≥95%).

## CI-exact matrix

All commands used `GOTOOLCHAIN=go1.24.13`, `GOFLAGS=-mod=mod`, and PATH prefixed
with `/Users/jperla/josh/repos/tr/quill-router/.venv/bin`. `GOCACHE` was relocated
to `/tmp/speculation-go-cache` because the user's default cache is read-only in
the sandbox. Lint emitted cache-persistence warnings for its separate default
cache; its exit status and diagnostics gate passed.

For each tag set:

```sh
go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run --allow-serial-runners --build-tags "$tags"
go vet -tags "$tags" ./...
go test -count=1 -tags "$tags" ./...
```

| Tags | golangci-lint | go vet | go test -count=1 |
|---|---|---|---|
| cloud_aws,llm_bedrock | PASS | PASS | PASS |
| cloud_aws,llm_multi | PASS | PASS | PASS |
| cloud_gcp,llm_vertex | PASS | PASS | PASS |
| cloud_gcp,llm_multi | PASS | PASS | PASS |
| cloud_azure,llm_multi | PASS | PASS | PASS |

Final matrix process exits and elapsed times:

```text
cloud_aws,llm_bedrock lint: exit 0 (7.5s)
cloud_aws,llm_bedrock vet: exit 0 (1.1s)
cloud_aws,llm_bedrock test: exit 0 (22.5s)
cloud_aws,llm_multi lint: exit 0 (2.5s)
cloud_aws,llm_multi vet: exit 0 (0.6s)
cloud_aws,llm_multi test: exit 0 (19.7s)
cloud_gcp,llm_vertex lint: exit 0 (2.4s)
cloud_gcp,llm_vertex vet: exit 0 (0.5s)
cloud_gcp,llm_vertex test: exit 0 (21.8s)
cloud_gcp,llm_multi lint: exit 0 (2.5s)
cloud_gcp,llm_multi vet: exit 0 (0.6s)
cloud_gcp,llm_multi test: exit 0 (22.3s)
cloud_azure,llm_multi lint: exit 0 (3.2s)
cloud_azure,llm_multi vet: exit 0 (0.7s)
cloud_azure,llm_multi test: exit 0 (21.9s)
```

`gofmt -l enclave-go/internal/speculation`: clean (empty output).
`git diff --check`: clean.

`TestNoProductionImports`: PASS. Independent grep:

```sh
rg -n '"[^" ]*/internal/speculation"' enclave-go --glob '*.go' --glob '!**/*_test.go' --glob '!**/speculation/**'
```

No matches (rg exit 1).

## File list

All paths below are under `enclave-go/internal/speculation/`:

- `protocol.go`, `json.go`, `cost.go`, `verdict.go`
- `protocol_test.go`, `robustness_test.go`
- `testdata/mutate.go`, `mutations.json`, `mutation-report.md`
- `README.md`, `verification.md`
- `testdata/speculation_v1/grant-permit-tokens.json`
- `testdata/speculation_v1/protocol-vectors.json`
- `testdata/speculation_v1/verdict-vectors.json`
- `testdata/speculation_v1/provider-wire.json`
- `testdata/speculation_v1/rules.json`
- `testdata/speculation_v1/manifest.json`

Final `git status --short`, from the repository root:

```text
?? enclave-go/internal/speculation/
```
