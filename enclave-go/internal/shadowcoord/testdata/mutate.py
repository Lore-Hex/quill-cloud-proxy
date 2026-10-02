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
     "health = saved.evidence.Health", "if c.Mono()>5*time.Second {delete(c.workspaceClosed,x.identity.WorkspaceID)}; health = saved.evidence.Health",
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

MUTANTS += [('observer-panic-escapes',
  'internal/shadowobserve/boundary.go',
  'defer func() {\n\t\tif recover() != nil {\n\t\t\towner.Fault()\n\t\t}\n\t}()',
  '',
  './internal/trustedrouter',
  'TestReviewObserverPanicPreservesOrdinarySuccess'),
 ('refresh-worker-panic-escapes',
  'internal/shadowcoord/coordinator.go',
  'func (c *Coordinator) RefreshOnce(ctx context.Context, refresh Refresh) {\n\tdefer c.Recover()',
  'func (c *Coordinator) RefreshOnce(ctx context.Context, refresh Refresh) {',
  './internal/shadowcoord',
  'TestRefreshPanicFailsClosedAndCountsLoss'),
 ('forget-original-grant-receipt',
  'internal/shadowcoord/coordinator.go',
  'receipt, seen := original.receipts[fingerprint]',
  'receipt, seen := original.receipts[fingerprint]; seen = false',
  './internal/shadowcoord',
  'TestReviewReplayAfterMissCannotRenewMonotonicDeadline'),
 ('unbounded-enclave-concurrency',
  'internal/shadowcoord/coordinator.go',
  'c.unresolved >= MaxUnresolved',
  'false',
  './internal/shadowcoord',
  'TestReviewEnclaveUnresolvedCapacity'),
 ('unbounded-simulated-memory',
  'internal/shadowcoord/coordinator.go',
  'c.memory > MaxSimulatedMemory-InvocationMemory',
  'false',
  './internal/shadowcoord',
  'TestSimulatedMemoryAndRelease'),
 ('finish-leaks-ownership',
  'internal/shadowobserve/execution.go',
  'x.finished = true\n\tx.c.Release(x.identity, x.id)',
  'x.finished = true',
  './cmd/enclave',
  'TestReviewHandlerEarlyCredentialReturnLeaksSlot'),
 ('unresolved-denial-ignored',
  'internal/shadowcoord/coordinator.go',
  'status == 402 || status == 429 || status == 401 || status == 403',
  'false',
  './internal/shadowcoord',
  'TestReviewUnresolvedWorkspaceDenialInvalidatesCoverage'),
 ('resolved-scope-discarded',
  'internal/trustedrouter/client.go',
  'controlErr.ShadowScope = shadowobserve.Identity{WorkspaceID: envelope.Data.WorkspaceID, KeyID: '
  'envelope.Data.KeyID, LookupDigest: envelope.Data.LookupDigest}',
  'controlErr.ShadowScope = shadowobserve.Identity{}',
  './internal/trustedrouter',
  'TestAuthenticatedErrorScopeCarriedToObserver'),
 ('caller-cancellation-poisons-health',
  'internal/trustedrouter/shadow.go',
  '} else if status != 0 {',
  '} else {',
  './internal/trustedrouter',
  'TestReviewCancellationNotInfrastructureFailure'),
 ('eager-off-mode-regexp',
  'internal/shadowobserve/wire.go',
  'import (\n\t"encoding/json"\n)',
  'import ("encoding/json";"regexp")\nvar eager = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)',
  './internal/shadowcoord',
  'TestOffModePackageInitAllocations'),
 ('duplicate-response-identity',
  'internal/shadowobserve/wire.go',
  'delete(allowed, i.Identity)',
  '',
  './internal/shadowcoord',
  'TestReviewWireAdditionalBounds'),
 ('suppress-retry-health',
  'internal/trustedrouter/shadow.go',
  'c.shadowCall(func() { c.shadow.ObserveVerdict(lookup, 503, "infrastructure_error", "") })',
  '_ = lookup',
  './internal/trustedrouter',
  'TestShadowRetryTimingAndByteParity'),
 ('fallback-measured-as-first-route',
  'internal/shadowobserve/execution.go',
  'x.authorized && first && x.decision.Eligible',
  'x.authorized && x.decision.Eligible',
  './internal/shadowcoord',
  'TestFallbackIsNotProposedRoute'),
 ('decoder-size-guard-removed',
  'internal/shadowobserve/wire.go',
  'len(body) > MaxResponseBytes',
  'false',
  './internal/shadowcoord',
  'TestReviewWireAdditionalBounds'),
 ('refresh-signer-signs-ordinary',
  'internal/trustedrouter/shadow.go',
  'c.shadowSigner = signer',
  'c.shadowSigner = signer; c.stageDBootSigner = signer',
  './internal/trustedrouter',
  'TestShadowBootOnlyHeaderParity'),
 ('evaluate-under-coordinator-lock',
  'internal/shadowcoord/coordinator.go',
  'snapshot := speculation.EvaluateEligibility(s.cached.received, s.evidence.Local, req, health, '
  'speculation.Monotonic(c.Mono()))',
  'c.mu.Lock(); snapshot := speculation.EvaluateEligibility(s.cached.received, s.evidence.Local, '
  'req, health, speculation.Monotonic(c.Mono())); c.mu.Unlock()',
  './internal/shadowcoord',
  'Test64PredecisionsDoNotHoldLockDuringEvaluation'),
 ('unchecked-route-claim',
  'internal/shadowcoord/coordinator.go',
  'r, ok := claims["route"].(map[string]any)',
  'r := claims["route"].(map[string]any); ok := true',
  './internal/shadowcoord',
  'TestVerifiedTierCeilingAndClaimShapes'),
 ('skip-tier2-ceiling',
  'internal/shadowcoord/coordinator.go',
  'if tier == 2 {',
  'if tier == 200 {',
  './internal/shadowcoord',
  'TestVerifiedTierCeilingAndClaimShapes'),
 ('decode-before-input-length-check',
  'internal/shadowcoord/coordinator.go',
  'if speculation.CheckInputLength(len(body)) != speculation.ReasonEligible {',
  'if false {',
  './internal/shadowcoord',
  'TestInputLengthRejectsBeforeDecode'),
 ('uncapped-record-rate',
  'internal/shadowcoord/coordinator.go',
  'c.emitCount >= 100',
  'false',
  './internal/shadowcoord',
  'TestRecordRateAndVisibleLoss'),
 ('mixed-module-imports',
  'cmd/enclave/main.go',
  '\n'
  '\t"bufio"\n'
  '\t"bytes"\n'
  '\t"context"\n'
  '\t"crypto/sha256"\n'
  '\t"encoding/json"\n'
  '\t"errors"\n'
  '\t"fmt"\n'
  '\t"io"\n'
  '\t"net"\n'
  '\t"net/http"\n'
  '\t"os"\n'
  '\t"os/exec"\n'
  '\t"os/signal"\n'
  '\t"strconv"\n'
  '\t"strings"\n'
  '\t"sync"\n'
  '\t"syscall"\n'
  '\t"time"\n'
  '\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/abuse"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/apihosts"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"\n'
  '\tbatchapi "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bootstrap"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/entropy"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/imagegen"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/privatemode"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/requesttiming"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"\n'
  '\t"golang.org/x/crypto/acme/autocert"',
  '\n'
  '\t"bufio"\n'
  '\t"bytes"\n'
  '\t"context"\n'
  '\t"crypto/sha256"\n'
  '\t"encoding/json"\n'
  '\t"errors"\n'
  '\t"fmt"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"\n'
  '\t"io"\n'
  '\t"net"\n'
  '\t"net/http"\n'
  '\t"os"\n'
  '\t"os/exec"\n'
  '\t"os/signal"\n'
  '\t"strconv"\n'
  '\t"strings"\n'
  '\t"sync"\n'
  '\t"syscall"\n'
  '\t"time"\n'
  '\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/abuse"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/apihosts"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"\n'
  '\tbatchapi "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bootstrap"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/entropy"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/imagegen"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/privatemode"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/requesttiming"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"\n'
  '\t"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"\n'
  '\t"golang.org/x/crypto/acme/autocert"',
  './cmd/enclave',
  'TestShadowModuleImportGroups')]

MUTANTS += [("identity-index-change-not-revalidated", "internal/shadowcoord/coordinator.go",
             "func (c *Coordinator) index(id Identity) {\n\tc.revision++",
             "func (c *Coordinator) index(id Identity) {", "./internal/shadowcoord",
             "TestSnapshotRevalidatesNewLookupAmbiguity")]

MUTANTS += [("unbounded-authenticated-denial-scopes", "internal/shadowcoord/coordinator.go",
             "!c.workspaceClosed[id.WorkspaceID] && len(c.workspaceClosed) >= MaxIdentities",
             "false", "./internal/shadowcoord", "TestAuthenticatedDenialScopeMemoryBound")]

MUTANTS += [("internal-timeout-as-caller-cancellation", "internal/trustedrouter/shadow.go",
             "caller.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))",
             "(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))",
             "./internal/trustedrouter", "TestShadowInternalDeadlineClosesHealth")]

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
