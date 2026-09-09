# ScaleDown rollout

Native task adapter for `scaledown/compress`, `scaledown/summarize`,
`scaledown/extract`, and `scaledown/classify`. The hosted API at
`https://api.scaledown.xyz` uses `x-api-key` and four native task paths, not the
currently unavailable `/v1/chat/completions` endpoint. See the router's
`docs/scaledown.md` for the public request contract.

The provider reports billable input including internal task preprocessing.
Output is free. The adapter rejects missing/malformed usage before output;
the selected-model billing contract preserves a real zero output count.
The control plane keeps these tasks on exact global settlement, not a
regional lease that can clamp an overrun to the original caller estimate.

## Deployment Order

1. Publish `SCALEDOWN_API_KEY` from the local operator keyfile independently to
   each cloud. Never expose it to the control-plane runtime or logs.
2. Deploy the enclave adapter through the normal staged, attestation-checked
   regional rollout. Verify direct provider secret loading.
3. Only then publish the router catalog and hourly refresh binding. Publishing
   catalog routes before the native adapter is deployed causes failed calls.
4. Smoke all four tasks with synthetic text and verify exact input-only usage,
   credits debits, and refund/idempotency behavior.

AWS: `quill/trustedrouter-scaledown-api-key` was created in `eu-west-1` and
verified replicated `InSync` to `eu-west-3` on 2026-09-09. New images also need
the parent bootstrap mapping and vsock 8086 to `api.scaledown.xyz:443`.

Azure: a **separate, not-yet-serving** bundle was sealed on 2026-09-09, leaving
the active production bundle unchanged. For the staged Azure rollout use:

```sh
export BUNDLE_SECRET=tr-bootstrap-bundle-scaledown-20260909
export QUILL_AZURE_BUNDLE_VERSION=5e554cb23fcd4f9d8dc3d2a0d0fe8aea
```

The checked-in bundle manifest names that prepared version. Rebuild/rebind the
measured policy using the normal Azure runbook; do not merely restart old
instances with a new bundle or widen attestation checks. Retain old pins until
all rolled instances verify.

GCP: provision `trustedrouter-scaledown-api-key` and grant secret-level read
access to the workload identity and the price-refresh deployment identity.
The default local ops identity cannot manage secrets; obtain authorized deploy
credentials before this step. Do not merge the catalog while this is blocked.

## Verification

The gated `TestScaleDownLive` test makes four tiny requests. Load only
`SCALEDOWN_API_KEY` into its environment, set `SCALEDOWN_LIVE_TEST=1`, then run:

```sh
go test -tags 'cloud_gcp,llm_multi' ./internal/llm -run '^TestScaleDownLive$' -count=1 -v
```

Also run the focused fake-server tests, billing tests, and full
`cloud_gcp,llm_multi`, `cloud_aws,llm_multi`, and `cloud_azure,llm_multi` suites.
Never log task text or raw upstream errors in production. ScaleDown is ZDR
under its public DPA, but is not an attested/E2EE provider.
