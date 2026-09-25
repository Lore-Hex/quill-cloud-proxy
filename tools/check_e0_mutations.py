#!/usr/bin/env python3
"""Run E0 regression mutations on a disposable COPY, never the working module."""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
copy = Path(tempfile.mkdtemp(prefix="e0-mutations-", dir="/tmp")) / "enclave-go"
shutil.copytree(root / "enclave-go", copy, ignore=shutil.ignore_patterns(".git", "*.test"))
# No Go module files or fixtures in the user's tree are mutated.
env = dict(os.environ, GOTOOLCHAIN="auto", GOPROXY="off", GOFLAGS="-mod=mod", GOCACHE="/tmp/gocache-e0")
tr = "./internal/trustedrouter"
cmd = "./cmd/enclave"
S = "internal/trustedrouter/spend_lease.go"
C = "internal/trustedrouter/stage_c.go"
A = "internal/trustedrouter/authorization_retry.go"
R = "TestStageCReserveCommitThenResponseLostRouterReplay"
P = "TestStageCPlanOwnershipAndTombstones"
M = "TestStageCReplayAcceptanceMatrix"
O = "TestChatOrdinaryAuthorizeReplayUnchanged"
H = "TestServeOneStageCLostAckReplayExecutesAndFinalizesOnce"
Q = "TestStageCReplayOnlyReducesCapacity"
mutations = []

def add(name, file, old, new, test, failures, package=tr):
    mutations.append((name, file, old, new, test, failures, package))

add("M01 restore nonce-only replay", S, "if !marked && decoded.Data.IdempotentReplay", "if decoded.Data.IdempotentReplay", R, [R])
add("M02 disable transport recovery", S, "policy.retryable = retryableAdmissionAuthorizationError", "policy.retryable = retryableAuthorizationError", R, [R])
add("M03 lose authority on transport failure", "internal/trustedrouter/client.go", 'return nil, i, fmt.Errorf("trustedrouter: post %s: %w", path, err)', 'return nil, -1, fmt.Errorf("trustedrouter: post %s: %w", path, err)', R, [R])
add("M04 trust imported owner", C, "owner := explicitAuthorizationInvocation(ctx)\n\tif owner == nil || owner != p.owner", "owner := p.owner\n\tif owner == nil || owner != p.owner", P+"/different_invocation_same_nonce", [P+"/different_invocation_same_nonce"])
add("M05 accept copied plan identity", C, "owner.plans[p.key] != p || p.entered", "false || p.entered", P+"/copied_plan", [P+"/copied_plan"])
add("M06 bypass plan entry", C, "if !plan.enterReserve(ctx, c, req.IdempotencyKey)", "if false && !plan.enterReserve(ctx, c, req.IdempotencyKey)", P+"/reconstructed_receipt", [P+"/reconstructed_receipt"])
add("M07 ignore consumed entry claim", C, "|| p.entered || claimed", "|| p.entered || (false && claimed)", P+"/consumed_claim", [P+"/consumed_claim"])
add("M08 allow reentry/cancelled reserve", C, "|| p.entered || claimed", "|| (false && p.entered) || claimed", "TestStageCConcurrentReserveEntersOnce|"+P+"/cancelled", ["TestStageCConcurrentReserveEntersOnce",P+"/cancelled"])
add("M09 forget prepare tombstone", C, "used || owner.plans[idempotencyKey] != nil", "used", P+"/repeat_prepare", [P+"/repeat_prepare"])
add("M10 let ordinary call steal plan", A, "registered != plan", "false && registered != plan", P+"/ordinary_cannot_claim_plan", [P+"/ordinary_cannot_claim_plan"])
add("M11 rebuild mutable request", C, "defer plan.admission.Release()", 'defer plan.admission.Release()\n plan.body, _ = json.Marshal(admissionAuthorizeBody(c, plan.lookupHash, chatAuthorizeBody(c, plan.lookupHash, req.IdempotencyKey, req, plan.routeType), plan.admission))', P+"/frozen_request", [P+"/frozen_request"])
add("M12 trust mutable Local", C, "admissionAuthorizationMatches(p.frozen, a)", "admissionAuthorizationMatches(p.Local, a)", P+"/frozen_local", [P+"/frozen_local"])
add("M13 omit full marked validation", S, "if err := plan.validateAcceptance(&decoded.Data); err != nil", "if err := plan.validateAcceptance(&decoded.Data); false && err != nil", M, [M+"/"+n for n in ["false_marker_matching_nonce","missing_hash","wrong_hash","missing_authorization","missing_remaining","negative_remaining","over_cap_remaining","workspace","key","route","candidate","region","billing","alias"]])
add("M14 misclassify malformed markers", S, "return nil, controlPlaneEndpoint, invalidAdmissionResponse()", "return nil, controlPlaneEndpoint, idempotencyReplayConflict()", M, [M+"/"+n for n in ["null_marker","scalar_marker","bad_member_type"]])
add("M15 exempt unmarked admission replay", S, "if !marked && decoded.Data.IdempotentReplay", "if plan == nil && decoded.Data.IdempotentReplay", M, [M+"/unmarked_absent_nonce",M+"/unmarked_different_nonce"])
add("M16 reject legal unmarked responses", S, "if !marked && decoded.Data.IdempotentReplay", "if plan != nil && !marked { return nil, controlPlaneEndpoint, idempotencyReplayConflict() }; if !marked && decoded.Data.IdempotentReplay", M, [M+"/unmarked_matching_nonce",M+"/unmarked_fresh"])
add("M17 accept ordinary wrong nonce", S, "if !marked && decoded.Data.IdempotentReplay", "if plan != nil && !marked && decoded.Data.IdempotentReplay", O, [O+"/absent",O+"/different"])
add("M18 reuse ordinary claim", A, "if _, exists := i.claimed[idempotencyKey]; exists", "if _, exists := i.claimed[idempotencyKey]; false && exists", O, [O+"/matching"])
add("M19 change canonical Stage C body", S, '"api_key_hash":           lookupHash,', '"invocation_nonce": "accidental-nonce", "api_key_hash": lookupHash,', R, [R])
add("M20 drift transport retry bytes", A, "for attempt := 1; attempt <= policy.attempts; attempt++ {", "for attempt := 1; attempt <= policy.attempts; attempt++ { if attempt > 1 { body = append(body, ' ') }", R, [R])
add("M21 substitute authorization", C, "return decoded, true, nil", 'decoded.AuthorizationID = "replacement"; return decoded, true, nil', R, [R])
add("M22 handler lost ack regression", S, "if !marked && decoded.Data.IdempotentReplay", "if decoded.Data.IdempotentReplay", H, [H], cmd)
add("M23 handler settlement substitution", C, "return decoded, true, nil", 'decoded.AuthorizationID = "replacement"; return decoded, true, nil', H, [H], cmd)
add("M24 forget downward observation", C, 'decoded.SpendLeaseRemainingMicro, "", true,', 'nil, "", true,', Q+"/100000$", [Q+"/100000"])
add("M25 allow capacity increase", "internal/spendlease/state.go", "if *ledgerRemaining >= local || current.remaining.CompareAndSwap(local, *ledgerRemaining)", "if current.remaining.CompareAndSwap(local, *ledgerRemaining)", Q+"/1000000$", [Q+"/1000000"])
add("M26 invent fallback owner", C, "owner := explicitAuthorizationInvocation(ctx)", "owner := authorizationInvocationFromContext(ctx)", P+"/no_invocation", [P+"/no_invocation"])
add("M27 permit changed attempt key", C, "|| key != p.key", "|| (false && key != p.key)", P+"/changed_key", [P+"/changed_key"])
add("M28 permit changed client", C, "|| client != p.client", "|| (false && client != p.client)", P+"/different_client", [P+"/different_client"])
add("M29 reject different stored nonce even when marked", S, "if !marked && decoded.Data.IdempotentReplay", "if decoded.Data.IdempotentReplay", M+"/marked_different_nonce", [M+"/marked_different_nonce"])

add("M30 drift transport retry proof", A, "for attempt := 1; attempt <= policy.attempts; attempt++ {", 'for attempt := 1; attempt <= policy.attempts; attempt++ { if attempt > 1 { bootAuthHeader += "drift" }', R, [R])
add("M31 redispatch marked chat", "cmd/enclave/main.go", "if !marked {", "if !marked || marked {", H, [H], cmd)

print(f"COPY: {copy}", flush=True)
def run(package, test):
    return subprocess.run(["go","test","-tags","cloud_gcp,llm_multi",package,"-run",test,"-count=1","-timeout=15s"], cwd=copy, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
baseline = run(tr, "Test(StageC|ChatOrdinary)")
if baseline.returncode:
    print(baseline.stdout); raise SystemExit("copy baseline failed")
print("PASS: copy baseline", flush=True)
for name, file, old, new, test, failures, package in mutations:
    path = copy/file
    original = path.read_text()
    assert old in original, (name, old)
    # Replace only the specified occurrence; restore from in-memory baseline.
    path.write_text(original.replace(old,new,1))
    try:
        result = run(package,test)
        (copy.parent/(name.split()[0]+".log")).write_text(result.stdout)
        observed = set(re.findall(r"--- FAIL: ([^\s]+)",result.stdout))
        missing = set(failures)-observed
        if result.returncode == 0 or missing or "[build failed]" in result.stdout:
            print(result.stdout)
            raise SystemExit(f"INVALID/SURVIVED: {name}; missing assertion failures {missing}")
        print(f"KILLED {name}: {', '.join(failures)}", flush=True)
    finally:
        path.write_text(original)
print(f"PASS: {len(mutations)} mutations killed by named assertion failures; original module untouched", flush=True)
