#!/usr/bin/env python3
"""PR E regression mutations on a disposable copy; no git writes."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
work = Path(tempfile.mkdtemp(prefix="pr-e-mutations-", dir="/tmp"))
module = work / "enclave-go"
shutil.copytree(root / "enclave-go", module)
env = dict(os.environ, GOTOOLCHAIN="go1.24.13", GOFLAGS="-mod=mod",
           GOCACHE="/tmp/pr-e-go-build")
source = "internal/trustedrouter/async_settlement.go"
client = "internal/trustedrouter/client.go"
mutations = [
    ("A_drop_flag", client, "if c.asyncNegotiate && asyncCohort(routeType)",
     "if asyncCohort(routeType)", "TestAsyncAuthorizeNegotiationGuards/false/chat.completions"),
    ("B_non_cohort", client, "if c.asyncNegotiate && asyncCohort(routeType)",
     "if c.asyncNegotiate", "TestAsyncAuthorizeNegotiationGuards/true/messages"),
    ("C_ignore_eligible", source, "|| !bool(a.AsyncEligible)", "",
     "TestAsyncEligibilityAndTicketGuards/not_eligible|TestAsyncExpiryAndUsageFallback/ineligible"),
    ("D_sync_required_accepted", source,
     'asyncLog("sync_required", asyncReason(reply.Data.Reason))\n\t\treturn nil, false, "sync_required"',
     'return &SettleResult{CostMicrodollars: 2, CostMicrodollarsKnown: true}, false, ""',
     "TestAsyncAllSyncRequiredReasons"),
    ("E_changed_retry_payload", source,
     "if first && time.Unix(a.expires, 0).Sub(c.asyncNow()) >= asyncTicketMargin {\n\t\tfor attempt := 1; attempt <= policy.attempts; attempt++ {",
     "if first && time.Unix(a.expires, 0).Sub(c.asyncNow()) >= asyncTicketMargin {\n\t\tfor attempt := 1; attempt <= policy.attempts; attempt++ {\n"
     "if attempt > 1 { raw = []byte(strings.Replace(string(raw), `\"input_tokens\":1`, `\"input_tokens\":2`, 1)) }",
     "TestAsyncResponseDecisionsAndRetryIdentity/server_error"),
    ("F_catalog_reprice", source,
     "evaluation, err := billingv1.Evaluate(a.snapshot, usage.SelectedEndpoint, raw, observed)",
     # Simulate a catalog refresh replacing the signed price program. Keep the
     # final envelope validator: its refusal must also fail the positive test.
     "catalog, _ := billingv1.BuildSnapshot([]billingv1.Endpoint{{ID: usage.SelectedEndpoint, Provider: \"openai\", ModelID: \"catalog/model\", UsageType: \"Credits\", InputMicroPerMillion: 9000000, OutputMicroPerMillion: 9000000, Tiers: []billingv1.EndpointTier{}}}, observed)\n"
     "evaluation, err := billingv1.Evaluate(catalog, usage.SelectedEndpoint, raw, observed)",
     "TestAsyncBuilderAllPositiveBillingCases"),
    ("skip-signature-verification", "internal/receipt/compact_verify.go",
     '!ed25519.Verify(key, parts.SigningInput, parts.Signature)',
     '(!ed25519.Verify(key, parts.SigningInput, parts.Signature) && false)',
     "TestAsyncTicketSignatureVerification/zero_signature"),
    ("legacy-fallback-when-snapshot-sync-available", source,
     'result, hard, err := c.snapshotSyncSettlement(retryCtx, endpoint, raw, hash, a.charge, auth)',
     'result, hard, err := (*SettleResult)(nil), true, errors.New("network")',
     "TestAsyncSnapshotSyncRecovery/finalized_fixture"),
    ("refund-on-cleanup-timeout", "cmd/enclave/main.go",
     'fmt.Fprintln(os.Stderr, "enclave.async_settle event=cleanup_timeout")',
     'deliveredOutput = false; settledBeforeTerminal = false; return nil, fmt.Errorf("provider completion timeout")',
     "TestAsyncStreamFinalFrameJoinAndPendingMetadata/(chat.completions|responses)-cleanup-timeout"),
    ("metadata-after-completed", "internal/adapter/responses.go",
     'if err := writeSettlementMetadata(w, control, result, true); err != nil {\n\t\t\treturn err\n\t\t}\n\n\t\tif err := writeResponseEventSeq(w, seq, terminalEvent.name, terminalEvent.body); err != nil {\n\t\t\treturn err\n\t\t}',
     'if err := writeResponseEventSeq(w, seq, terminalEvent.name, terminalEvent.body); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif err := writeSettlementMetadata(w, control, result, true); err != nil {\n\t\t\treturn err\n\t\t}',
     "TestAsyncStreamFinalFrameJoinAndPendingMetadata/(responses|responses-stage-d)$"),

    ("drop-ticket-lifetime", "internal/trustedrouter/async_ticket_claims.go",
     " || c.Exp-c.Iat > 300", "",
     "TestAsyncTicketClaimRules/lifetime_301"),
    ("skip-canonical-payload", "internal/trustedrouter/async_ticket_claims.go",
     "!bytes.Equal(canonical, raw)", "(!bytes.Equal(canonical, raw) && false)",
     "TestAsyncTicketClaimRules/payload_whitespace"),
    ("accept-extra-claim", "internal/trustedrouter/async_ticket_claims.go",
     "len(fields) != len(names)", "len(fields) < len(names)",
     "TestAsyncTicketClaimRules/extra_claim"),
    ("metadata-after-incomplete", "internal/adapter/responses.go",
     'if err := writeSettlementMetadata(w, control, result, true); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t\tif err := writeResponseEventSeq(w, &seq, "response.incomplete", map[string]any{"type": "response.incomplete", "response": response}); err != nil {\n\t\t\t\treturn err\n\t\t\t}',
     'if err := writeResponseEventSeq(w, &seq, "response.incomplete", map[string]any{"type": "response.incomplete", "response": response}); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t\tif err := writeSettlementMetadata(w, control, result, true); err != nil {\n\t\t\t\treturn err\n\t\t\t}',
     "TestAsyncStageDTerminalOrder/responses"),
    ("retry-finalized-duplicate", source,
     'if resp.StatusCode == http.StatusOK && a.Status == "duplicate" {',
     'if resp.StatusCode == http.StatusOK && a.Status == "duplicate" && false {',
     "TestAsyncFinalizedDuplicate"),

    ("accept-duplicate-without-envelope", source,
     'len(final.Data.Acceptance) != 0 && final.Data.Final == nil',
     'len(final.Data.Acceptance) != 0 && final.Data.Final == nil && false',
     "TestAsyncDuplicateEnvelopeRecovery/(async-v1|sync)/(missing_envelope|null_envelope)"),
    ("skip-issuer-equality", source,
     ' || claims.Iss != c.asyncTicketKeys[kid].issuer',
     ' || (claims.Iss != c.asyncTicketKeys[kid].issuer && false)',
     "TestAsyncTicketIssuerBinding"),
    ("keyring-entry-without-issuer-accepted", source,
     'issuer, encoded, found := strings.Cut(entry, "~")',
     'issuer, encoded, found := strings.Cut(entry, "~"); if !found { issuer, encoded, found = "router-fixture", entry, true }',
     "TestAsyncKeyringMalformedEntries/without_issuer"),
]

def run(test, package="./internal/trustedrouter"):
    packages = package.split()
    return subprocess.run(["go", "test", "-count=1", "-timeout=60s", "-tags",
                           "cloud_gcp,llm_multi", *packages, "-run", test],
                          cwd=module, env=env, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)

baseline = run("TestAsync", "./internal/trustedrouter ./internal/adapter ./cmd/enclave")
(work / "baseline.log").write_text(baseline.stdout)
if baseline.returncode:
    raise SystemExit("Disposable baseline failed: " + str(work))
print("Baseline PASS; evidence: " + str(work), flush=True)
for name, file, old, new, test in mutations:
    path = module / file
    original = path.read_text()
    assert original.count(old) == 1, (name, original.count(old))
    path.write_text(original.replace(old, new, 1))
    try:
        result = run(test, "./cmd/enclave" if name in ("refund-on-cleanup-timeout", "metadata-after-completed") else "./internal/adapter" if name == "metadata-after-incomplete" else "./internal/trustedrouter")
        (work / (name + ".log")).write_text(result.stdout)
        failed = re.findall(r"--- FAIL: ([^\s]+)", result.stdout)
        if result.returncode == 0 or not failed or "[build failed]" in result.stdout:
            raise SystemExit(name + " SURVIVED or failed to compile; see " + str(work))
        print(name + " KILLED by " + ", ".join(failed[:3]), flush=True)
    finally:
        path.write_text(original)
