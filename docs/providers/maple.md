# Maple pilot qualification

## Verified update automation

`Verify Maple release` checks the signed production approval every 30 minutes.
It does not learn pins from the live server, accept every vendor-signed build,
or change any request's attestation policy at runtime.

The reviewed baseline is `enclave-go/maple-transport/verified-release.json`.
Only changes under `apps/`, `docs/`, the root README/license/agent instructions,
and the four measurement-approval files are eligible automatically. Every
other path is protected by default, including new paths, submodules, build
recipes, dependencies, authentication, cache isolation, routing and downstream
worker measurements. A changed protected tree creates one review issue per
source commit and cannot publish a new pin without operator approval.

For an eligible change, an independent credential-free ARM64 job rebuilds the
complete EIF using locked source and Nix, a checked sandbox, and only the
NixOS binary cache. All four release files must match byte for byte. GitHub
provenance must bind the exact repository identity, source commit, main vendor
branch, workflow and OIDC issuer; the P-384 approval history must be append-only
and correctly signed. A separate clean job checks the positive attestation and
deliberate wrong-pin rejection without sending credentials or inference.

Only clean acquisition and publication jobs receive the release bot token;
neither executes vendor code. The rebuild cannot modify the original artifacts
or the verification code, because a fresh job performs the comparison.
Publication rechecks the current approval and protected tree, creates a two-file pin/evidence PR, waits for full
CI on that exact head, and merges without an admin bypass. The existing GCP
signed release and staged canary workflow then applies. AWS and Azure still
require their shared rollout guard, measured-image publication and regional
canaries; this workflow does not claim a merge has deployed those fleets.
Rebuilds run only for eligible changes or an explicitly dispatched review-only
qualification. Review-only evidence can never authorize automatic publication.
Large image artifacts are transferred between isolated jobs, deleted after
verification, and expire after one day if cleanup fails. Small evidence records
are retained for one day and included in the generated pin PR.

The only qualified managed model remains
`deepseek-v4-1-flash-1017-uncensored`. Dealign is its weights publisher, not an
upstream API call. Auto models, stock DeepSeek, shared Tinfoil routes and all
other Maple models remain rejected before the encrypted helper is started.
Changes to the dedicated worker are security-sensitive even if the model name
is unchanged. Provider deployment overlap is still necessary to avoid an
outage while a new security-sensitive release is reviewed and staged.

## Approved worker identity update (2026-11-09)

The exact candidate tracked in [review #716](https://github.com/Lore-Hex/quill-cloud-proxy/issues/716)
replaces the front PCR0 with
`769e8dd045dad30df5bb13e4fe8ced547c64f906316fc6e8519a0e858cd8cdb2690bdcf66c9dad3ed5e5d0a37768189a`.
It binds source `d8fa269c9155d800ab9f6e8f8897c8e154492711` and the signed
production approval `cd52297dba7bd2d0718722d89039d3c4cb4132f1`.
The former `3a67fa1c...` measurement is replaced, not retained.
Joseph explicitly approved this exact worker-identity update on November 9,
2026, subject to fresh verification, full CI and the normal guarded rollout.
This approval is not production deployment or inference acceptance, and does
not authorize clearing another release's reservation.

On November 9, a fresh credential-free check with the previously approved
`3a67fa1c...` pin failed. The unchanged reviewed candidate passed front
attestation in 164 ms, followed by deliberate wrong-pin rejection after its
positive control. No credential or inference was sent. Two reported production
requests failed in US Central and Europe with one Maple attempt, no fallback,
and no response bytes. Their sanitized logs do not preserve the underlying
exception, so these checks establish the trust-transition failure without
claiming to identify every individual request's internal error.

The independent credential-free ARM64 build in
[run 42227131805](https://github.com/Lore-Hex/quill-cloud-proxy/actions/runs/42227131805)
matches `image.eif`, `pcr.json`, `SHA256SUMS` and `handoff.json` byte for byte.
EIF SHA-256 is
`9174c64b51a1948f2d3067e134c6794c8323a4e6978a56edcc475ac1fb1903d6`.
The reviewed verifier also passed exact-source GitHub/Sigstore provenance
and the append-only P-384 approval history checks. This is independent
reproduction, not acceptance of the live server's advertised pin.

The dedicated uncensored workload moves from i02 to i01. Its worker policy
changes to release `v0.1.0+b300`, image
`6a8e906bc31caaccf5b6bbe84dec99c7213ec1d77aa360df464d531744590ac2`,
and CVM version 0.14.17. The protected tree hash therefore changes and this
update cannot qualify for automatic publication. The managed model still
selects only that dedicated attested worker. Stock DeepSeek's separate i02
and shared Tinfoil routes remain outside the managed route; the helper's
one-model admission restriction is unchanged.

Fresh CPU/platform/TLS evidence and wrong-nonce, wrong-pin and tamper controls
for the new worker are recorded in review #716. The front-pin regression failed
against the previous compiled pin first. After the update, 142 SDK/helper unit
tests passed with one live integration ignored, and 24 policy/update tests
passed. A credential-free front handshake passed in 186 ms, followed by
deliberate wrong-pin rejection. These handshake checks sent no inference.
The helper's `end_to_end_qualified=false` and
`source_reproduction_verified=false` describe its limited scope, not the
separate source rebuild or downstream evidence.
Required CI, fresh trust verification, measured cloud builds, signed trust
publication and production canaries remain release gates.
The protected-tree baseline in this proposal changes only for this reviewed
identity; future security-sensitive changes must still stop for review.

## Earlier front measurement update (2026-11-06)

This update proposes replacing the sole front PCR0 with
`3a67fa1c4317d83e77d74123f4e658c4a1a7b15a7a1f6e1e872612390a6499a50118f2dddf05bd034b0318c4bcef53f4`.
The previous `db70ca1d...` measurement is not retained as an additional
allowance. This is a proposal, not a deployment or operator approval.
Fresh approval of this exact measurement, CI, measured release builds,
signed publication and staged cloud checks remain required.

Maple's [approval PR #1475](https://github.com/MaplePrivacyLabs/Maple/pull/1475),
merged at `8b764796193690504cbe01be121a08177bfbe7b3`, appends one signed
measurement for source `13d75aa71c9bf0670d71bd6cf453a8fcf497f226`.
The P-384 history signature verifies using the SDK-pinned key; verifying that
signature over the previous measurement fails. Previous history is unchanged.
The artifact from [release 42114907636](https://github.com/MaplePrivacyLabs/Maple/actions/runs/42114907636)
passed GitHub/Sigstore provenance verification constrained to that exact
source, `refs/heads/master`, GitHub's OIDC issuer and the
`opensecret-eif-release.yml` workflow. This is not sole reliance on its
self-hosted build runner: an independent reproduction was performed.

The clean source, submodules, locked inputs and unchanged vendor build script
were rebuilt on ARM64 with `sandbox=true`, `sandbox-fallback=false`, and a
derivation proving the `/build` directory. Only `cache.nixos.org` was enabled;
no Maple or FlakeHub output cache was used. The complete 234,362,261-byte EIF,
`pcr.json`, `SHA256SUMS` and `handoff.json` match the published artifact byte
for byte. EIF SHA-256 is
`5506eeb07eeb8ece1e9be6b5c1d4616f50362b7ba711c99a991499ba07e47242`.
PCR1 remains
`a91689e37a54303051f68263010f397ddfa92d66e17df7a03a6777c33ff1e4fc12b69bbbe786894d43dcba1cf6d60aaa`;
PCR2 is
`4a3eaf8258a233da63c4aa6609fa8365ddb46eb162ab1710f6effa92785534d58c432f9105cb35fb632b6dc2150d2849`.
The vendor build passed 1,105 Rust tests; 55 database/live tests were ignored,
not claimed as passed.

The scoped comparison from `b3d45af5...` adds Kimi K3.1 Pro configuration and
its Tinfoil route. Other changed enclave Rust files add Kimi tests. The managed
explicit DeepSeek route, Transport V2, authentication, cache namespace
ownership and dedicated i02 worker/weights policy are unchanged. The two
parent-side Nitro Python container recipes update pinned apt packages and
disable vulnerable download retries. Desktop Linux packaging gains a glibc
floor and compiler settings; these do not replace the reproduced EIF recipe.
This is a scoped integration review, not a complete audit of Maple or its
live database. The earlier bundled proxy source-comparison limitations below
still apply; no broader source-equivalence claim is made.

During this investigation the existing approved pin failed its credential-free handshake.
The isolated AWS candidate also failed before completing a Maple canary,
while its parent TLS tunnel was healthy and managed credentials matched the
configured source. No serving AWS gateway was rolled. This is evidence for
the measurement-transition diagnosis, not an attribution of every historical
provider error.

The new pin regression failed against the previous constant before the update.
The SDK/helper unit-test scope passed 142 tests, with one live integration
ignored. A credential-free handshake using the new pin passed in 243 ms, and
the subsequent wrong-pin negative control passed after its positive control.
The vendor's separate account-management integration suite requires its
disposable backend and was not successfully run. No credentials or inference
were sent during these handshake checks. The qualification client's
`end_to_end_qualified=false` and `source_reproduction_verified=false` fields
remain honest: that client does not perform the independent rebuild or
downstream verification itself.

## Front measurement update (2026-11-05)

This change proposes only PCR0
`db70ca1d96a458ccea64cc995fb5c5f908b187e32293267e15e8a5677ac12a864c0b90abec6493f777060c95ece729da`.
The superseded `9d6ec6db...` measurement is replaced, not added as another
allowance. Production deployment remains gated on specific operator approval,
CI, measured builds, signed trust publication and staged cloud verification.

Maple's [approval PR #1443](https://github.com/MaplePrivacyLabs/Maple/pull/1443),
merged as `c3b8ad45c2cf1c0512fa34c1981500aedad0de42`, binds the measurement to
source `b3d45af55377e9c8fabdbf414fc3d835d3913fe4`. The enclave artifact from
[release 41798490334](https://github.com/MaplePrivacyLabs/Maple/actions/runs/41798490334)
passed GitHub/Sigstore verification constrained to that exact source,
`refs/heads/master`, GitHub's OIDC issuer and the repository's
`opensecret-eif-release.yml` workflow. The signed production history preserves
all previous entries and appends one. Its P-384 signature verifies with the
SDK-pinned history key and rejects the previous measurement as its message.
The signing runner is self-hosted; independent reproduction is required below.

An independent ARM64 build of the unchanged source and locked inputs passed
with Determinate Nix 3.23.3 (Nix 2.35.3), `sandbox=true`,
`sandbox-fallback=false`, and a derivation proving the `/build` directory.
Only `cache.nixos.org` was enabled, not Maple or FlakeHub output caches. The
full 234,346,327-byte EIF, `pcr.json`, `SHA256SUMS` and `handoff.json` match the
published artifact byte for byte. EIF SHA-256 is
`c6a9613084fef00e809dc4067e1f33d1bac41559fa5ddb204727c850425fe593`.
Independent EIF v4 structure and CRC validation passed. PCR1 remains
`a91689e37a54303051f68263010f397ddfa92d66e17df7a03a6777c33ff1e4fc12b69bbbe786894d43dcba1cf6d60aaa`;
PCR2 is
`f7016dc3e17997198a6c6756e4f9a850412ebab172b6bd59ab26e488460559c5b680b9ad7eb1aa33b0df7b2c75270ea5`.
The build passed 1,105 Rust tests; 55 database/live tests were ignored, not
claimed as passed.

The scoped review from `0e7dbc0b...` covers 18 commits. Encrypted Transport V2,
API-key authentication, cache namespace ownership, dedicated i02 hardware and
weights policy and entrypoint are unchanged. The managed explicit model still
has only its dedicated i02 route. Stock DeepSeek's weighted routing and Auto
Quick defaults changed separately; they do not select the managed explicit
model. Chat now requires a confirmed paid billing plan and fails closed on an
unknown plan. A new optional client-attribution header is limited to three
enum values, excluded from upstream headers, and adds no content to usage
events. JWT-only Responses title generation follows Auto Quick and retains
bounded pre-send fallback; it is outside TR's managed stateless chat path.
The locked Nix inputs and Markdown parser changed and are covered by the exact
rebuild. This is a scoped integration review, not a complete audit of Maple's
applications, deployment or live database.

The pin regression failed against the previous constant and passed with the
new pin. The SDK/helper workspace passed 142 tests, with one live integration
ignored. A credential-free live front handshake passed in 211 ms, followed by
deliberate wrong-pin rejection. No inference was sent during those checks.
The qualification client's `end_to_end_qualified=false` and
`source_reproduction_verified=false` remain honest: it does not perform the
independent build or downstream verification itself. Production acceptance is
still required before this update is described as serving.

## Front measurement update (2026-11-01)

The source now pins only PCR0
`9d6ec6dbcdbb282aa80f48e39a497284f5b3d86a06b6a2ac401b14a43eb6632b3255d2fe82417c13109209f3b7b72bdb`.
The previous `6eac0f15...` and original `ada74c7a...` measurements are not
additional allowed measurements. This source change is **not production rollout
or paid-inference acceptance**; all ordinary source CI, measured-image, signed
trust, cloud rollout and final production gates still apply.

From about 23:00 UTC on 2026-11-01, every GCP gateway's Maple attempt failed
fast before inference with a generic error, on VMs that had succeeded earlier
that day. Maple had approved a new production measurement at 22:37 UTC, so the
`6eac0f15...` pin was correctly refusing the new front enclave. This motivated
the review below; it does not prove the precise cause of each failed request.
No live measurement was copied into the allowlist.

Maple's [approval commit](https://github.com/MaplePrivacyLabs/Maple/commit/ae650d6e76e909a64606e7ab383c77414c51e5ae)
(PR #1421, a direct child of the source commit on `master`) binds the new
measurement to source `0e7dbc0bd4aac03db1e64cb8c733480d527fb450` and EIF SHA-256
`895a58e45c5eefd00561a372fedb615357ae7c159f83f0596925538a7f1ef1c0`.
Its new `pcrProdHistory.json` entry's signature verifies over that PCR0 with
OpenSecret's P-384 history key pinned in the vendored SDK; the same signature
fails over the previous PCR0, and the previous entry's signature still verifies.
The artifacts from release runs
[41357568942](https://github.com/MaplePrivacyLabs/Maple/actions/runs/41357568942)
and [41357392934](https://github.com/MaplePrivacyLabs/Maple/actions/runs/41357392934)
are identical. Their `image.eif` and `pcr.json` passed GitHub/Sigstore provenance
verification constrained to that exact source, `refs/heads/master`, GitHub's
OIDC issuer, and
`MaplePrivacyLabs/Maple/.github/workflows/opensecret-eif-release.yml@refs/heads/master`.
As for the previous release, the attesting build ran on a self-hosted
(Blacksmith ARM) runner, so `--deny-self-hosted-runners` does not pass; the
independent build below is what removes reliance on that runner.

An independent ARM64 Linux build of that clean source, its locked inputs and
its pinned `privatemode-public` submodule (`4b72dcbb...`) then completed the
unchanged vendor packaging script successfully. It used the vendor-pinned
Determinate Nix 3.23.3 (Nix 2.35.3), `sandbox=true`, `sandbox-fallback=false`,
and an actual derivation proving the `/build` directory. Only `cache.nixos.org`
was enabled; no Maple/FlakeHub output cache was used. The full 234,339,943-byte
EIF, `pcr.json`, `SHA256SUMS` and `handoff.json` are byte-for-byte identical to
the published artifact. Independent EIF v4 structure and CRC validation passed.
PCR1 is unchanged at
`a91689e37a54303051f68263010f397ddfa92d66e17df7a03a6777c33ff1e4fc12b69bbbe786894d43dcba1cf6d60aaa`;
PCR2 is
`bb1e353c9a8f753c40f8c709bb463de646320218d49c6d038aac69eda4df228e78fcd480ef8246d830d09cc99e6065ba`.
The build's Rust checks passed 1,092 tests, with 55 ignored database/live tests;
this is not a claim those ignored integrations passed. As on 2026-10-31, the
first attempt stopped at the sandbox preflight under Docker's masked `/proc`;
the same unmasked container setup fixed it without disabling the Nix sandbox or
allowing fallback.

The scoped source comparison from `55f02f0b...` to `0e7dbc0b...` (44 commits)
found no blocking change in the managed stateless chat path. Transport V2,
API-key and OpenAI-compatible authentication, chat completions, provider
routing and caches, workspace cache ownership, the dedicated i02 attestation
policy and its worker/weights pins, `main.rs`, the Cargo lockfile, Nix flake
inputs, the SDK and the i02 entrypoint/planning sources are unchanged. Every
changed enclave Rust file belongs to the Responses/Conversations compaction
feature, including one `db.rs` accessor for it. Responses compaction now streams after
durable acceptance, with content-free progress events, and the Responses system
prompt points Maple self-questions at maple.ai. A new
`GET /v1/conversations/:id/compactions` route returns user-scoped marker
metadata only. It sits behind the existing JWT layer, and its SQL binds every
caller value; only a validated `asc`/`desc` enum selects the fragments. These
JWT-protected routes were inspected, not claimed as a complete audit of that
subsystem or its live database. The remaining changes are Maple agent and
research app, update-publisher, download-tracking and CI code outside the EIF,
plus approval files and docs.

At 06:34 UTC on 2026-11-02, the unchanged qualification client with the reviewed
new pin passed a live front handshake (430 ms in that observation). Its
deliberate wrong-pin check then passed after a successful positive control.
These checks used no credentials and sent no inference. The client's metadata
still conservatively reports `end_to_end_qualified=false` and
`source_reproduction_verified=false`: the handshake does not itself perform the
independent build described above. Pinned Rust 1.94.1 formatting and Clippy
passed; the SDK/helper workspace checks passed 142 tests with one live test
ignored. Deployment and fresh paid acceptance remain separate requirements.

## Front measurement update (2026-10-31)

That update pinned only PCR0
`6eac0f156a3732f05a83de99cef6e429c8b67a43b4cea9af27b419bc3e979b4d6494e9625baff8a22327d60be235851a`.
The old `ada74c7a...` measurement was not an additional allowed measurement.
That source change was **not production rollout or paid-inference acceptance**;
all ordinary source CI, measured-image, signed trust, cloud rollout and final
production gates still apply. The sections below preserve the earlier pilot
and reproduction history rather than describing the new rollout's state.

Maple's [approval commit](https://github.com/MaplePrivacyLabs/Maple/commit/665be3441841f8e53cc2350ce800a17a7810e557)
binds the new measurement to source
`55f02f0bbd584f40b0e1fea9936551f7e5e6b31c` and EIF SHA-256
`88c4e9c3a72f470bdacddc9d7c1e167d4cb52636fad37f1e0480bb0889c57c7f`.
The artifact from [release run 41151904767](https://github.com/MaplePrivacyLabs/Maple/actions/runs/41151904767)
passed GitHub/Sigstore provenance verification constrained to that exact source,
`refs/heads/master`, GitHub's OIDC issuer, and
`MaplePrivacyLabs/Maple/.github/workflows/opensecret-eif-release.yml@refs/heads/master`.

An independent ARM64 Linux build of that clean source and locked inputs then
completed the unchanged vendor packaging script successfully. It used the
vendor-pinned Determinate Nix 3.23.3 (Nix 2.35.3), `sandbox=true`,
`sandbox-fallback=false`, and an actual derivation proving the `/build`
directory. Only `cache.nixos.org` was enabled; no Maple/FlakeHub output cache
was used. The full 234,229,623-byte EIF and `pcr.json` are byte-for-byte identical
to the published artifact. Independent EIF v4 structure and CRC validation
passed. PCR1 is
`a91689e37a54303051f68263010f397ddfa92d66e17df7a03a6777c33ff1e4fc12b69bbbe786894d43dcba1cf6d60aaa`;
PCR2 is
`4218ec0efecc0c90635cbecb8e40e8dc5e7893d5dc10dd70476a6b4f925db54604dc15cfdddc24b8604ca227b59e2851`.
The build's Rust checks passed 1,078 tests, with 54 ignored database/live tests;
this is not a claim those ignored integrations passed. An earlier local attempt
stopped at isolation preflight and produced no qualifying artifact. Restoring
the previously used container filesystem setup fixed that preflight without
disabling the Nix sandbox or allowing fallback.

The scoped source comparison from `7957ce78...` to `55f02f0b...` found no blocking
change in the managed stateless chat path: Transport V2 implementation, API-key
authentication, provider routing, workspace cache ownership, the dedicated i02
attestation policy, and its worker/weights pins are unchanged. The shared SSE
refactor adds frame and queue bounds for internal Responses helpers; ordinary
chat retains its existing settings, usage accounting and no-ambiguous-replay
rules. The new internal-account gate is Dev-only and remains behind authentication.
The Nitro Enclaves SDK C update to 0.4.6 incorporates the previously applied
entropy and cleanup fixes. Responses compaction is a separate JWT-protected
route; its user-scoped encrypted checkpoint boundaries were inspected, not
claimed as a complete audit of that new subsystem or its live database.

At 17:21 UTC, the previous gateway source's first final Maple request returned
HTTP 502 and testing stopped without replay. A separate no-credential,
no-inference handshake using the old pin returned the SDK's combined
attestation/PCR-policy rejection. This motivated the independently sourced
review above; it does not prove the precise cause of the paid request's 502.
No live measurement was copied into the allowlist, and no plaintext fallback,
remote-history trust, secret, SDK protocol, or deployment gate was changed.

At 17:43 UTC, the unchanged qualification client with the reviewed new pin
passed a live front handshake (409 ms in that observation), then its deliberate
wrong-pin check passed after a successful positive control. These checks used
no credentials and sent no inference. The client's metadata still conservatively
reports `end_to_end_qualified=false` and `source_reproduction_verified=false`:
the handshake does not itself perform the independent build described above.
Pinned Rust 1.94.1 formatting and Clippy passed; the SDK/helper workspace checks
passed 142 tests with one live test ignored. Deployment and fresh paid acceptance
remain separate requirements.

## Original pilot scope (2026-10-28)

**Not deployed or customer-routable.** This change adds a qualification client,
one-shot encrypted adapter, measured-image build stages, dispatch and cloud-local
secret coordinates. No cloud image, secret bundle or public catalog is activated.
The paired control-plane provider remains internal-only,
with Credits, BYOK, ZDR and confidential/E2EE eligibility all disabled.

The operator explicitly requested **Confidential**, confirmed resale permission
and zero API prompt/response retention on 2026-10-28. Policy confirmation is not
an attestation result. Do not activate a weaker plaintext or ZDR-only route to
work around the remaining confidential-path gates.

The requested model is `deepseek-v4-1-flash-1017-uncensored`. Keep it separate
from stock DeepSeek. At the supplied source commit it routes only to Maple's
dedicated i02 worker; stock DeepSeek can also route to shared Tinfoil.

## Qualification client

`enclave-go/maple-transport` source-pins Maple's Rust SDK at
`c668d817dceec5c2e7390de7c68a581c88ea2eea` and locks its dependencies. The
`prepare-sdk.sh` step verifies the full source archive SHA-256 before extracting
the SDK and applying `sdk-dependencies.patch`: only HKDF 0.12 to 0.13 and SHA-2
0.10 to 0.11 change. Transport, attestation and cryptographic protocol source is
unchanged. It uses
the vendor's Transport V2 implementation, including Nitro certificate/COSE
verification, fresh challenge and client/server key binding, directional
encryption, ordered frames and authenticated finality. No custom crypto or
bearer-only HTTP fallback is implemented here.

The original pilot client accepted only candidate PCR0
`ada74c7aa10cbde75f83d7ec674cc4fc4a4cf9cc555e367189fbec332dffa985c6082ae4647fd50242a590bf9cd1d3f0`,
the latest production-history entry in that immutable source snapshot.
Remote-history trust is disabled. That was a qualification pin, not an approval
of the live source/image binding or of the downstream GPU/model. A mismatch is
a stop condition; do not replace it with whichever measurement the server sends.

Maple's [measurement approval commit](https://github.com/MaplePrivacyLabs/Maple/commit/942efea0bfcbb7523d320186404dcb4cd8f27c0a)
attributes this PCR0 to backend source
`7957ce78ad8eee7a173a9d877ff6e320876894c8` and EIF SHA-256
`9702de6b825bb024d843fb840bf1c638ca7443bbd6ba49f93d14f6e6dfc60e23`,
published by [release run 40226283053](https://github.com/MaplePrivacyLabs/Maple/actions/runs/40226283053).
The downloaded EIF's GitHub/Sigstore attestation now verifies with both the exact
source digest and the expected release workflow identity constrained. This
authenticates the published artifact provenance, not an independent source rebuild.

An independent ARM64 Linux Nix build at the exact source and locked inputs
completed successfully, but produced PCR0
`8ce7b06eee78c7b067cf8657c72f826ebe5ef3a80d4f341e55e9449d795b4d88e9cbc4ecf5fef5243a670b9118724329`
and EIF SHA-256
`1f6ea511e63a211cf247190af75df27208e11a68a685a1ca2b1a49b3d89da242`.
PCR1 and PCR2 differ too. Both evaluations select the same Nix output path
`/nix/store/x4p7gxc5jmagz41l5pxgd699ni7m0z72-opensecret-eif-prod`;
the vendor workflow restored it from FlakeHub while the independent run built it.
The independent container used upstream Nix rather than the vendor's pinned
Determinate Nix 3.23.3, so this is a reproducibility discrepancy requiring
investigation, not proof of a malicious image. Do not substitute the new PCR0
for the live pin or claim independent reproduction passed.

The discrepancy was subsequently traced to Nix silently falling back to an
unsandboxed build when Docker refused its nested `/proc` mount. Checking only
`sandbox=true` was insufficient: `sandbox-fallback=true` embedded temporary
build paths instead of the vendor's `/build`. The new isolated builder uses
the exact pinned Determinate version, `sandbox=true`, `sandbox-fallback=false`,
and a preflight derivation that proves its build directory is `/build`.
No Maple/FlakeHub output cache is enabled. Its complete user initramfs now
matches the published artifact byte-for-byte at SHA-256
`dd6edd1895a87f425025f4ce4ff0f037a1ef4534ba3ea9b5a32979c6bef28234`.
The enforced-sandbox build completed on 2026-10-29. Its full 233,941,161-byte
EIF matches the published artifact byte-for-byte: SHA-256
`9702de6b825bb024d843fb840bf1c638ca7443bbd6ba49f93d14f6e6dfc60e23`.
PCR0 matches the approved pin above; PCR1 is
`a91689e37a54303051f68263010f397ddfa92d66e17df7a03a6777c33ff1e4fc12b69bbbe786894d43dcba1cf6d60aaa`
and PCR2 is
`a48fbff25a1920a7e982aa421cdfd94dd189e2c024b075048ad3f0b93b0fd67b82187d8c26d6e75e35772e742de05ed6`.
The independent kernel also matches at SHA-256
`06d3b4c1a7b3b0a9253a50c0baea3bc4ba0f791deb2e24abfdb752a1f3022740`.
The vendor's outer packaging script stopped after exporting the valid image and
measurements because the test container lacked `jq`; independent JSON parsing,
EIF structural/CRC validation and whole-file SHA-256 comparison verified the
exported artifacts. This is a successful image reproduction, not a successful
exit of that packaging wrapper. Neither result implies a TR production rollout.

```sh
sh enclave-go/maple-transport/prepare-sdk.sh
cargo test --locked --manifest-path enclave-go/maple-transport/Cargo.toml
cargo run --locked --manifest-path enclave-go/maple-transport/Cargo.toml -- attest
cargo run --locked --manifest-path enclave-go/maple-transport/Cargo.toml -- reject-pin
cargo run --locked --manifest-path enclave-go/maple-transport/Cargo.toml -- reject-key
# Supply MAPLE_API_KEY from the operator secret loader, never as a command argument.
cargo run --locked --manifest-path enclave-go/maple-transport/Cargo.toml -- probe
cargo run --locked --manifest-path enclave-go/maple-transport/Cargo.toml -- cache
```

`probe` uses the account key and paid inference: one discovery, one JSON
and one SSE synthetic PONG request, each capped at 1,024 output tokens. `cache`
adds three bounded synthetic requests: cold, warm and a separate cache namespace.
Inference
send budget is exactly one per request: no automatic replay after uncertain
delivery. The client checks exact model identity, PONG content, normal finish,
integer token counts, cached-token bounds and streaming usage. Cumulative
streaming counts may begin at zero; they must be monotonic, are never added
together, and require a nonzero terminal usage snapshot for the PONG probe.
It drains SSE
through encrypted EOF even after `[DONE]`, so a missing authenticated terminal
record cannot be mistaken for success. Responses have time/size bounds.

Output contains only fixed-vocabulary errors and metadata. SDK debug logging
is not installed. Never print raw provider errors, response content, credentials,
session keys or cache roots. The wrong-key check uses a deliberate fake key and
does not test the real account's entitlement. Positive front attestation alone
is not end-to-end qualification.

Customer chat JSON and streaming route metadata derive `gateway_region` from
the gateway's local bootstrap region, not the control plane's accounting
`region`. Cross-cloud gateways can authorize against the GCP control plane;
its region is not evidence of the gateway's location. Unknown origins are
omitted, private-route masking remains in force, and neither this field nor a
regional gateway establishes the downstream GPU's location. Accounting fields,
settlement bytes, prices and admission rules are unchanged.

## Initial evidence (2026-10-28)

Local qualification against the production backend:

- Fresh front-enclave session accepted the exact candidate PCR0 above (235 ms
  in one observation; not an inference latency benchmark).
- A deliberately different PCR0 was rejected after a successful positive
  control handshake. The SDK returns a combined attestation/PCR rejection;
  network errors are not accepted as a passing negative test.
- Encrypted `GET /v1/models` with a deliberate invalid key returned logical
  HTTP 401, not a transport failure.
- The operator subsequently supplied `MAPLE_API_KEY` in the keyfile. It was
  loaded only into the test process environment, not printed or provisioned to clouds.
- Authenticated encrypted discovery returned 13 models including the requested
  uncensored ID. JSON and SSE PONG probes passed with exact model identity and
  integer usage. One completed run measured 1,036 ms for JSON (39 input/16 output)
  and 699 ms for SSE (39 input/4 output, first delta 699 ms). These are individual
  short-request observations, not a latency or incremental-delivery benchmark.
- The first stream probe exposed an overly strict test-client assumption that
  every usage snapshot was final and nonzero. Maple sends cumulative snapshots;
  the client now validates monotonic counters and final usage with a regression test.
- A fresh cache qualification sent 12,369 input tokens per call: cold cached 0,
  warm cached 12,288, a new independent namespace cached 0. Output counts were
  10/19/22. This verifies SDK namespace isolation locally, not production
  workspace isolation or account-debit reconciliation.
- The signed-in dashboard confirms the dedicated TrustedRouter key and an
  active Pro plan expiring November 28, 2026, with zero purchased extra credits.
  It does not expose per-request debits or the remaining included allowance.
  No subscription, purchase, or key changes were made.
- Local Claude CLI Opus review was attempted but OAuth refresh failed. No private
  Claude API key was substituted and no successful review is claimed.

## Dedicated worker qualification

The exact deployed front source pins i02 to
[`MaplePrivacyLabs/inference-deepseek-uncensored`](https://github.com/MaplePrivacyLabs/inference-deepseek-uncensored/tree/76a8e5fdaa7dbade1640025829ba0bfeae7a3495),
tag `v0.1.0-rc.1+b300`, digest
`1d92cd06f7b47179bf81612f6a41fdb0a329253affef1803f0cdeb5175cc80c4`.
A fresh nonce-bound worker report passed the pinned vendor verifier
[`f0fef79eec6a5a2c8592cf8aff4b90ab556acfbc`](https://github.com/MaplePrivacyLabs/tinfoil-rs/tree/f0fef79eec6a5a2c8592cf8aff4b90ab556acfbc).
Wrong nonce, wrong measurement and tampered CPU signature were rejected.
Attested `/health` succeeded before and after negative checks rejecting
plaintext HTTP, a different port and a wrong TLS key pin. No account credential
was sent to the worker. Its unauthenticated `/v1/models` returns 401; this is
not a successful catalog probe and must not be represented as one.

The measured worker config uses CVM v0.14.13, an immutable container digest,
and dm-verity verified weights at
`dealignai/DeepSeek-V4.1-Flash-1017-UNCENSORED-FP8@c19ca5ca4eaeb79d29fdf08aea8327da95b1116a`.
Source review of [CVM v0.14.13](https://github.com/tinfoilsh/cvmimage/tree/c3b4860d72e78baf61140778b92986b102716b87)
found that the measured config hash is checked before use; GPU appraisal runs
before serving and failures leave the GPU not ready. Model volumes are mounted
read-only through dm-verity. The Rust client binds device evidence into the
CPU report but delegates NVIDIA appraisal to this measured boot implementation.
Do not describe it as a separate NVIDIA signature verification by TR's client.

## Bundled proxy source comparison

The front image also contains a checked-in `continuum-proxy` executable.
`flake.nix` copies it rather than compiling it, and `entrypoint.sh` starts it
in the enclave. Reproducing the EIF alone therefore does not establish the
source of every executable in that image.

The pinned public submodule is
[`4b72dcbbd58940835b5ba32502c1e247721b9584`](https://github.com/edgelesssys/privatemode-public/tree/4b72dcbbd58940835b5ba32502c1e247721b9584).
Two independent local `nix build --no-update-lock-file .#privatemode-proxy.bin`
runs produced the same SHA-256:
`0d6e3df6333045d61a7bfeaea480304ed2aae22b4d847deab2e543d0f8124790`.
The checked-in executable is
`e87aaefe7dfcddd46446d7a41874ed422aeee9ccdc2f75d4c69c22dbd36157ec`.
Both are static Linux ARM64 builds using Go 1.26.4 with identical reported
dependency versions and build settings. The raw hashes **do not match**.

ELF section comparison found identical executable `.text` (SHA-256
`bf1fc8ab424b10de8f5be57bd8f18909fd8e4cc5211218ec99c7fd72d3e3337d`),
runtime tables, build information and initialized data at the same addresses.
Differences in `.rodata` are limited to three Nix store hashes for
`tzdata-2026b`, `mailcap-2.1.54` and `iana-etc-20251215`; their path suffixes
are unchanged. The shipped binary also has Go/GNU build IDs and different
symbol stripping. This narrows the discrepancy to build metadata and data-file
paths in the inspected sections; it is not a byte-for-byte binary reproduction
or a replacement for completing the full front-image comparison.

## Candidate serving protocol

`maple-transport` accepts one bounded JSON envelope on stdin: the managed API
key, a base64 32-byte cache root from the authorized workspace, and an OpenAI
chat body. It permits only the exact uncensored model with streaming enabled;
TR can aggregate that stream for non-streaming public requests. Backend and
PCR0 are compiled constants, not environment or request overrides. Caller cache
fields are removed and usage is mandatory. An SDK send budget of one forbids
automatic inference replay.

Output is one JSON status line followed by canonical SSE. The relay validates
model identity, integer cumulative token/cache counts and frame/response limits.
It withholds `[DONE]` until the SDK reports authenticated encrypted EOF.
Malformed/truncated streams and upstream error events never emit success.
Errors are fixed vocabulary; no tracing subscriber is installed.

One live synthetic adapter call passed with 36 input / 4 output tokens, cached
input 0 and authenticated completion (1,456 ms, not a latency benchmark).
All three multi-provider image recipes now source-build the static helper with
a locked dependency graph, and dispatch enters it before BYOK or generic HTTP.
These images are **not deployed**. The Go supervisor in `enclave-go/internal/maple`
adds:

- Credentials and request bodies over bounded stdin pipes, no command-line
  secrets or inherited provider environment; redacted subprocess failures.
- An explicit child-launch flag, dropped per-request UID/GID (65200-65231),
  cleared supplementary groups, no privilege gains and disabled core dumps.
  Ordinary startup never probes or closes inherited descriptors.
- At most 32 live children, a ten-minute request bound, cancellation/reaping and
  release of capacity only after the child exits. No automatic replay.
- Domain-separated cache roots from the server-authorized workspace scope;
  missing scopes use fresh independent roots.
- A second terminal gate withholding `[DONE]` until the authenticated helper
  stream ends and its process exits successfully.
- An AWS CONNECT tunnel allowing only `enclave.trymaple.ai:443`, forwarding
  opaque TLS through parent vsock port 8136. The deployment template includes
  this tunnel; ports 8132-8135 are reserved by the separate Bedrock
  Runtime work. No parent-host decryption is implemented.

The registered LLM adapter rejects BYOK, unpinned model
IDs, unsupported service tiers, embeddings and decision requests. Generic chat
and embedding helpers also reject Maple before any network request, including
provider overrides; resolving an ordinary HTTP client is forbidden. It preserves total input, cached subset and
output usage; and rejects missing finish/usage/terminal frames. Focused race
tests, the full LLM regression suite, and the AWS-tagged supervisor tests in a
network-isolated Linux container pass. A separate read-only scratch-image harness
with the actual launcher and static helper passed a live authenticated 401 using
a deliberately fake credential, with all capabilities dropped except SETUID and
SETGID and no privilege gains. This exercises the real per-request privilege drop
and attestation path, but is not a production rollout or a live AWS vsock test.

The same isolated Linux harness then completed one credentialed synthetic PONG
with 36 input and 4 output tokens in 1.50 seconds. Its API key arrived only on
stdin, the request used a fresh cache namespace, and completion required the
real helper's authenticated terminal frame and successful exit. Full race-enabled
Go suites pass for `cloud_gcp,llm_multi`, `cloud_aws,llm_multi` and
`cloud_azure,llm_multi`; 12 AWS parent bootstrap tests and the secret-source,
Azure bundle and vsock-map checks pass. These results do not assert production
deployment. The independent EIF discrepancy is resolved by the enforced-sandbox
reproduction above.

## Dependency-scan repair

The initial CI scan flags `block-buffer 0.10.4` under
[GHSA-qwgh-2vcv-g2f7](https://github.com/RustCrypto/utils/security/advisories/GHSA-qwgh-2vcv-g2f7).
The primary advisory lists the affected range as `>=0.11.0,<0.12.1`, whereas
the scanner's advisory data includes earlier versions. The SDK's SHA-2/HKDF
dependencies require the 0.10 line. Inspection of 0.10.4 shows a separate
`pos: u8` field, not the inline cursor targeted by the advisory; the other
resolved version, 0.12.1, is patched. No suppression or scan bypass has been added.
The candidate instead applies a two-line dependency-only patch to the exact SDK
source, selecting HKDF 0.13 and SHA-2 0.11, removing block-buffer 0.10 entirely.
The isolated upgraded SDK passed 122 unit tests, including backend key/record
vectors and tampered-attestation rejection; one upstream integration test remains
ignored because it requires the vendor's disposable backend. The workspace uses
one lockfile and runs SDK library tests alongside the TR relay tests. Required CI
and live encrypted regression results still govern promotion of this candidate.

## Remaining release requirements

1. Account identity, Pro expiry, reseller permission and API content-retention
   confirmation have been obtained. The operator key passes live probes. The
   unavailable remaining-allowance export is not an operator-approval blocker;
   do not purchase credits, renew a subscription or change payment settings.
2. Independent reproduction of the approved front enclave is complete, including
   exact EIF bytes and all three PCRs. The enforced downstream i02 worker release,
   GPU verification and model identity review and local positive/negative
   encrypted probes are recorded above. Preserve these immutable release pins.
3. Qualify all measured image builds and AWS TLS/vsock egress. The helper,
   explicit child entrypoint, dispatcher and deployment templates are wired;
   verify workspace isolation and process supervision in each exact release image.
   Preserve immutable pins and redacted failures.
4. Bill actual reported token usage at published rates: USD 0.65/0.13/1.45 per
   million uncached input/cached input/output tokens. On October 28 the operator
   instructed shipping without waiting for a debit export. Do not invent a
   rounding fee or USD 0.001 minimum on customer requests. The earlier pilot
   offer mentioned those provider debit rules, but the public rate page does not;
   provider-debit reconciliation remains unverified, not a user-input gate.
   Preserve normal billing-oracle, partial/error settlement and cache tests.
5. Run all cloud build/test variants and the normal coordinated rollout with
   region-by-region health/attestation/inference checks. Provision cloud-local
   secrets without replacing unrelated entries. Keep a healthy holdback cloud.
   Azure bundle `8df3ba4381d74315b2d1c696e63e839d` was sealed/uploaded on
   October 29, preserving all 83 names from `f397b1b83b324c11abf12a561296c02e`
   and adding only Maple (84 total). No serving container has switched to it.
   For the Maple rollout pin
   `QUILL_AZURE_BUNDLE_VERSION=8df3ba4381d74315b2d1c696e63e839d` and set
   `QUILL_MAPLE_SECRET=trustedrouter-maple-api-key`. Keep Hixtube, Privatemode,
   Telluvian and both System1 optional-secret settings; a dry run without
   Hixtube would omit an existing entry. Recheck for a newer bundle before use.
   `QUILL_MAPLE_SECRET` still defaults empty until this explicit measured opt-in.
6. Only after those gates, activate the control-plane model and qualified badges.

References: [proxy](https://maple.ai/docs/proxy),
[pricing](https://maple.ai/pricing), [terms](https://maple.ai/terms),
[privacy](https://maple.ai/privacy),
[wire contract](https://github.com/MaplePrivacyLabs/Maple/blob/c668d817dceec5c2e7390de7c68a581c88ea2eea/services/opensecret/docs/transport-v2-protocol.md),
[worker pins](https://github.com/MaplePrivacyLabs/Maple/blob/c668d817dceec5c2e7390de7c68a581c88ea2eea/services/opensecret/src/maple_inference.rs).
