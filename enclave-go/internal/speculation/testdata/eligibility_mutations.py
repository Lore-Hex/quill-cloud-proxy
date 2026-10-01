#!/usr/bin/env python3
"""Mutate isolated temporary copies; never write source or frozen fixtures.

Run from any directory. Every mutation must fail its named behavioral test.
Detailed logs and JSON results are retained in the printed temporary directory.
"""
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1]
DEST = Path(tempfile.mkdtemp(prefix="spec-e2b-mutations-"))
ENV = dict(os.environ, GOTOOLCHAIN="go1.24.13", GOFLAGS="-mod=mod")
ENV["PATH"] = "/Users/jperla/josh/repos/tr/quill-router/.venv/bin:" + ENV["PATH"]
ENV.setdefault("GOCACHE", "/private/tmp/spec-e2b-go-cache")
# (name, file, original, replacement, named test)
MUTATIONS = [
    ("receipt_time_ttl", "deadline.go",
     'time.Unix(g.StartDeadline(), 0).Sub(wall.Add(uncertainty))',
     'time.Duration(g.StartDeadline()-number(c, "iat"))*time.Second - uncertainty',
     "TestLateGrantCannotGainReceiptTTL"),
    ("nineteen_successes", "protocol.go", 'number(history, "count") >= 20',
     'number(history, "count") >= 19', "TestHistoryDistinctThreshold/nineteen"),
    ("retry_counted_twice", "protocol.go", 'number(history, "sequence") >= number(history, "count")',
     'number(history, "sequence") >= 0', "TestHistoryDistinctThreshold/retry_counted_twice"),
    ("chars4_method", "payload.go", 'cert.BoundAlgorithm != ConservativeUTF8Bytes',
     '(cert.BoundAlgorithm != ConservativeUTF8Bytes && cert.BoundAlgorithm != "chars/4")',
     "TestPayloadMisses/chars4"),
    ("chars4_bound", "payload.go", 'bound := int64(len(wire)) + cert.FramingTokens',
     'bound := int64(len(wire))/4 + cert.FramingTokens', "TestPayloadFramingSystemAndExactBounds"),
    ("default_512", "payload.go", 'default:\n\t\treturn 0, false',
     'default:\n\t\treturn 512, true', "TestPayloadMisses/cap_missing"),
    ("erase_caller_provenance", "eligibility.go", 'req.CallerIdempotency.header || req.CallerIdempotency.body || bodyKey',
     'bodyKey', "TestEligibilityExclusions/header_idempotency"),
    ("shadow_dispatch", "eligibility.go", 'r == ReasonEligible && g.grant.Shadow()',
     'r == ReasonEligible && false', "TestDispatchAuthoritySeparation"),
    ("lease_dispatch", "protocol.go", 'h["typ"] == typ, "type"',
     '(h["typ"] == typ || h["typ"] == "spend-lease+jws"), "type"', "TestDispatchAuthoritySeparation/spend-lease+jws"),
    ("missing_health", "health.go", '!h.Workspace.Known || !h.Key.Known || !h.ProviderKnown ||',
     'false ||', "TestMissingHealthAndScopedEpochs/workspace_missing"),
    ("confidential_host", "eligibility.go", 'if req.ConfidentialOnly {',
     'if false {', "TestEligibilityExclusions/confidential"),
    ("seam_one_byte", "payload.go", 'return prepared.Bytes, ReasonEligible',
     "return append(prepared.Bytes, ' '), ReasonEligible", "TestSeamAdapterParity"),
    ("ordinary_one_byte", "../llm/byok.go", '\n\t\tbytes.NewReader(bodyBytes),\n',
     "\n\t\tbytes.NewReader(append(bodyBytes, ' ')),\n", "TestChatPreparationDifferential/fixture-provider/fixture-text/stream=false/cap=false/implicit"),
    ("remove_precheck", "payload.go",
     '\tif r := precheckChat(req.Body, cert.SystemPrefix, cert.ProviderCacheScope, int(budget)); r != ReasonEligible {\n\t\treturn PreparedPayload{}, r\n\t}\n',
     '', "TestOversizedPayloadAllocations/text"),
    ("drop_stop", "payload.go", 'var req qtypes.OpenAIChatRequest',
     'delete(body, "stop")\n encoded, _ = json.Marshal(body)\n var req qtypes.OpenAIChatRequest', "TestSeamAdapterParity"),
    ("prefix_role", "payload.go", 'Role: "system", Content: text',
     'Role: "user", Content: text', "TestPayloadFramingSystemAndExactBounds"),
    ("older_workspace_epoch", "health.go", 'h.Workspace.Epoch != number(c, "workspace_epoch")',
     'h.Workspace.Epoch > number(c, "workspace_epoch")', "TestMissingHealthAndScopedEpochs/workspace_epoch_older"),
    ("older_key_epoch", "health.go", 'h.Key.Epoch != number(c, "key_epoch")',
     'h.Key.Epoch > number(c, "key_epoch")', "TestMissingHealthAndScopedEpochs/key_epoch_older"),
]

def run(root, test):
    return subprocess.run(["go", "test", "-count=1", "-v", "-run", "/".join("^" + re.escape(part) + "$" for part in test.split("/")), "./internal/llm" if test.startswith("TestChat") else "./internal/speculation"],
                          cwd=root, env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

baseline = DEST / "baseline"
shutil.copytree(SOURCE.parents[1], baseline)
check = subprocess.run(["go", "test", "-count=1", "./internal/speculation"], cwd=baseline,
                       env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(DEST / "baseline.log").write_text(check.stdout)
if check.returncode:
    raise SystemExit("Baseline failed: " + str(DEST / "baseline.log"))
results = []
for name, file, old, new, test in MUTATIONS:
    root = DEST / name
    shutil.copytree(baseline, root)
    target = root / "internal/speculation" / file
    source = target.read_text()
    if source.count(old) != 1:
        raise SystemExit(f"Expected exactly one edit for {name}")
    target.write_text(source.replace(old, new))
    result = run(root, test)
    (DEST / (name + ".log")).write_text(result.stdout)
    if "[build failed]" in result.stdout or "[setup failed]" in result.stdout:
        status = "build-broken"
    elif result.returncode and "--- FAIL: " + test.split("/")[0] in result.stdout:
        status = "red"
    else:
        status = "survived"
    results.append(dict(mutation=name, test=test, status=status, exit=result.returncode))
    print(f"{name}: {status} — {test}", flush=True)
(DEST / "results.json").write_text(json.dumps(results, indent=2) + "\n")
print("Evidence:", DEST)
raise SystemExit(0 if all(r["status"] == "red" for r in results) else 1)
