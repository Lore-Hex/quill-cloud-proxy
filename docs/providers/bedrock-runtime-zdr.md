# Bedrock Runtime Claude qualification

Not deployed. This candidate adds exactly five managed Claude routes through
Bedrock Runtime, not Mantle: Sonnet 5.5, Opus 5.5, Haiku 5.5, Sonnet 5 and Opus
4.8. Each uses its exact `us.anthropic.*` inference profile via us-east-1.
Do not blanket-label the existing Mantle catalog ZDR.

## Account evidence

On 2026-10-28 the Runtime account retention mode was `none` in us-east-1 and
us-west-2. us-east-2 was changed from `inherit` to `none` and read back. Ohio
mutation request ID: `ea461a18-9e36-49c5-af75-0b5dd426458a`.
All five US profiles were ACTIVE with exactly those three US destinations.
All five completed bounded PONG requests through Ohio:

| Model | AWS request ID |
| --- | --- |
| Sonnet 5.5 | 3a1dec47-0253-4bdb-9f0e-d884f9c5f6ac |
| Opus 5.5 | a105e7eb-7f78-4ca6-bb45-9b610ba1fdc9 |
| Haiku 5.5 | 4c354a67-1a3a-4135-b4b7-69f859c0f075 |
| Sonnet 5 | ed99da49-e1f0-4146-a805-df1a21004832 |
| Opus 4.8 | fe79c040-6e20-4681-a2c4-3c23307185c2 |

The existing managed Bedrock credential also completed a Haiku 5.5 Runtime
request with 18 input and 5 output tokens, request ID
`9535dc9a-be78-4ac7-8222-79193ea98c91`. Its added IAM policy permits the five
exact US profiles, the three regional retention reads and their scoped invoke
resources; no global-profile permission was added. Mantle retention is unchanged.

On October 29, all five profiles also passed paid synthetic streaming through
this exact Go adapter, including fresh policy checks in all three regions,
integer cumulative usage, an assembled PONG answer, `end_turn`, and clean SDK
EOF before terminal success. Individual calls took 1.31-2.95 seconds; these are
short correctness probes, not performance benchmarks. The opt-in test is
`TestBedrockRuntimeLiveQualifiedProfiles`; ordinary CI skips it without a key.

The candidate checks all three regional Runtime retention settings before
every inference, with no cached positive result. Unknown/missing/error policies
fail closed. It accepts no BYOK override, unknown model/profile pair, nonstandard
service tier or one-hour cache-write request. Inference send attempts are limited
to one. Public terminal success is withheld until the SDK stream ends cleanly.

## Verified US pricing

Source: [AWS Bedrock pricing](https://aws.amazon.com/bedrock/pricing/), Anthropic,
**Geo and In-region Cross-region Inference**, region **US East (N. Virginia)**,
viewed 2026-10-29 UTC. Ohio displayed the same rates for these models.
Do not use the separate Global table; US pricing is 10% higher.
Amounts below are USD per million tokens, before TR's normal markup.

| Model | Input | Output | 5-minute cache write | Cache read |
| --- | ---: | ---: | ---: | ---: |
| Haiku 5.5 | 0.11 | 0.55 | 0.1375 | 0.011 |
| Haiku 5.5 long context | 0.55 | 2.75 | 0.6875 | 0.055 |
| Sonnet 5.5 | 2.20 | 11.00 | 2.75 | 0.11 |
| Opus 5.5 | 4.40 | 22.00 | 5.50 | 0.22 |
| Sonnet 5 | 2.20 | 11.00 | 2.75 | 0.22 |
| Opus 4.8 | 5.50 | 27.50 | 6.875 | 0.55 |

The [Haiku 5.5 model card](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-haiku-5-5.html)
defines the high rate above 100,000 prompt tokens (exactly 100,000 remains standard).
The [Anthropic pricing documentation](https://platform.claude.com/docs/en/about-claude/pricing)
counts uncached input, cache reads and cache writes toward that threshold;
the entire request uses the applicable tier. Add matching boundary tests before
catalog activation. Batch is N/A for these rows.
One-hour cache writes are published separately but are not enabled here because
the shared ledger currently represents only the five-minute tariff.

## Remaining work

- Stream-failure/terminal tests and full race-enabled GCP/AWS/Azure multi-provider
  suites pass locally, as does the repository Go lint gate. CI still gates release.
  Local Claude CLI Opus is signed out; no private API key was substituted.
- Add the exact Runtime model prices, context boundaries and endpoint-scoped ZDR
  eligibility to the control-plane parser/catalog. Preserve Mantle behavior.
- Ensure strict-ZDR routing cannot select an unqualified Mantle endpoint.
- Deploy through the normal coordinated AWS/GCP/Azure gates with a healthy
  holdback, then run regional live streaming/non-streaming and billing smokes.

References: [AWS retention](https://docs.aws.amazon.com/bedrock/latest/userguide/data-retention.html),
[Claude on Bedrock](https://platform.claude.com/docs/en/build-with-claude/claude-in-amazon-bedrock-research-preview).
