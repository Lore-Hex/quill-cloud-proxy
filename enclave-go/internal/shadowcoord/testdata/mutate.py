"""Run semantic faults only in a disposable source copy; never modify git or the source tree."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
GO = ["go", "test", "-count=1", "-tags", "cloud_gcp,llm_multi"]
MUTANTS = [
    ("decision-after-authorize", "internal/trustedrouter/spend_lease.go",
     "ctx, finishShadow := c.observeShadowAuthorize(ctx, lookupHash)",
     "ctx, finishShadow := ctx, (func(*Authorization,error))(nil); defer func(){_, f := c.observeShadowAuthorize(ctx,lookupHash); if f != nil {f(result,resultErr)}}()",
     "./internal/trustedrouter", "TestShadowSelfQualificationPredecisionBeforeNetwork"),
    ("predecision-before-credential-guard", "cmd/enclave/main.go", "credentialChecked := false",
     'ctx = predecideSpeculation(ctx,trGateway,bearer,body,attribution.IdempotencyPresent,"chat.completions",confidential,&types.OpenAIChatRequest{},false); credentialChecked := false',
     "./cmd/enclave", "TestShadowCredentialBackoffOrderingCounters"),
    ("five-second-cache-expiry-reopens-health", "internal/shadowcoord/coordinator.go",
     "health := s.evidence.Health", "if c.Mono()>5*time.Second {delete(c.workspaceClosed,x.identity.WorkspaceID)}; health := s.evidence.Health",
     "./internal/shadowcoord", "TestConcurrentRenewalDenyAndNoTimerRecovery"),
    ("extra-provider-call", "cmd/enclave/provider_stream.go",
     "err = br.InvokeStreaming(attemptCtx, req, anthropicReq, candidateWriter, option)",
     "err = br.InvokeStreaming(attemptCtx, req, anthropicReq, candidateWriter, option); _ = br.InvokeStreaming(attemptCtx,req,anthropicReq,io.Discard,option)",
     "./cmd/enclave", "TestShadowPhysicalMoneyOutputDifferential"),
    ("sum-a-p-as-measured-overlap", "internal/shadowobserve/execution.go", "r.ActualOverlap = 0",
     "if r.Authorize!=nil && r.Provider!=nil {r.ActualOverlap=r.Authorize.End-r.Authorize.Start+r.Provider.End-r.Provider.Start}",
     "./internal/shadowcoord", "TestSerialTimingAndDeniedEvidence"),
    ("guessed-denied-p-as-measured", "internal/shadowobserve/execution.go", "r.ActualOverlap = 0",
     "r.ActualOverlap = 0; if r.MeasuredP==nil {p:=time.Second;r.MeasuredP=&p}",
     "./internal/shadowcoord", "TestSerialTimingAndDeniedEvidence"),
    ("prompt-field-in-telemetry", "internal/shadowobserve/execution.go", "type Record struct {",
     'type Record struct { Prompt string `json:"prompt"`',
     "./internal/shadowcoord", "TestSuppressionJoinsAndTelemetryAllowlist"),
    ("renew-deadline-at-receipt", "internal/speculation/deadline.go", "deadline := mono + Monotonic(remaining)",
     "deadline := mono + Monotonic(30*time.Second)",
     "./internal/speculation", "TestLateGrantCannotGainReceiptTTL"),
    ("accept-enforce", "internal/shadowobserve/mode.go", 'case "enforce":',
     'case "enforce": return Shadow,nil; case "unreachable-enforce":',
     "./internal/shadowcoord", "TestMode"),
    ("unknown-miss-as-malformed-error", "internal/shadowobserve/wire.go", 'return nil, NewMiss(status, envelope.Miss)',
     'if envelope.Miss=="future-code" {return nil,NewMiss(status,"malformed-response")}; return nil, NewMiss(status, envelope.Miss)',
     "./internal/shadowcoord", "TestUnknownMissTyping"),
]

def main():
    env = dict(os.environ, GOTOOLCHAIN="go1.24.13", GOFLAGS="-mod=mod",
               GOCACHE="/tmp/quill-e4-go-cache")
    env["PATH"] = "/Users/jperla/josh/repos/tr/quill-router/.venv/bin:" + env["PATH"]
    reports = Path(tempfile.mkdtemp(prefix="quill-e4-mutation-results-"))
    result = []
    with tempfile.TemporaryDirectory(prefix="quill-e4-mutation-copy-") as temp:
        copy = Path(temp) / "enclave-go"
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "node_modules"))
        for name, relative, old, new, package, test in MUTANTS:
            path = copy / relative
            original = path.read_text()
            if old not in original:
                raise RuntimeError(f"missing mutation site: {name}")
            command = GO + [package, "-run", "^" + test + "$"]
            def run(label):
                completed = subprocess.run(command, cwd=copy, env=env, text=True,
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                (reports / (name + "-" + label + ".log")).write_text(completed.stdout)
                return completed
            baseline = run("baseline")
            if baseline.returncode:
                raise RuntimeError(f"baseline failed: {name}: {baseline.stdout}")
            try:
                fault = original.replace(old, new, 1)
                if name == "predecision-before-credential-guard":
                    late = "ctx = predecideSpeculation(ctx, trGateway, bearer, body, attribution.IdempotencyPresent, routeType, confidential, &req, resolvedCustomModel != nil)"
                    if late not in fault:
                        raise RuntimeError("missing original predecision seam")
                    fault = fault.replace(late, "", 1)
                path.write_text(fault)
                mutated = run("mutant")
            finally:
                path.write_text(original)
            restored = run("restored")
            killed = mutated.returncode != 0 and ("--- FAIL: " + test) in mutated.stdout and "[build failed]" not in mutated.stdout
            row = dict(mutant=name, test=test, baseline=baseline.returncode,
                       killed=killed, restored=restored.returncode)
            result.append(row)
            print(json.dumps(row), flush=True)
        (reports / "results.json").write_text(json.dumps(result, indent=2))
        print("logs=" + str(reports), flush=True)
    if not all(r["killed"] and r["restored"] == 0 for r in result):
        raise SystemExit(1)

if __name__ == "__main__":
    main()
