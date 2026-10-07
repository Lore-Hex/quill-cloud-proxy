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
     "for attempt := 1; attempt <= policy.attempts; attempt++ {",
     "for attempt := 1; attempt <= policy.attempts; attempt++ {\n"
     "if attempt > 1 { raw = []byte(strings.Replace(string(raw), `\"input_tokens\":1`, `\"input_tokens\":2`, 1)) }",
     "TestAsyncResponseDecisionsAndRetryIdentity/server_error"),
    ("F_catalog_reprice", source,
     "evaluation, err := billingv1.Evaluate(a.snapshot, usage.SelectedEndpoint, raw, observed)",
     # Simulate a catalog refresh replacing the signed price program. Keep the
     # final envelope validator: its refusal must also fail the positive test.
     "catalog, _ := billingv1.BuildSnapshot([]billingv1.Endpoint{{ID: usage.SelectedEndpoint, Provider: \"openai\", ModelID: \"catalog/model\", UsageType: \"Credits\", InputMicroPerMillion: 9000000, OutputMicroPerMillion: 9000000, Tiers: []billingv1.EndpointTier{}}}, observed)\n"
     "evaluation, err := billingv1.Evaluate(catalog, usage.SelectedEndpoint, raw, observed)",
     "TestAsyncBuilderAllPositiveBillingCases"),
]

def run(test):
    return subprocess.run(["go", "test", "-count=1", "-timeout=60s", "-tags",
                           "cloud_gcp,llm_multi", "./internal/trustedrouter", "-run", test],
                          cwd=module, env=env, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)

baseline = run("TestAsync")
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
        result = run(test)
        (work / (name + ".log")).write_text(result.stdout)
        failed = re.findall(r"--- FAIL: ([^\s]+)", result.stdout)
        if result.returncode == 0 or not failed or "[build failed]" in result.stdout:
            raise SystemExit(name + " SURVIVED or failed to compile; see " + str(work))
        print(name + " KILLED by " + ", ".join(failed[:3]), flush=True)
    finally:
        path.write_text(original)
