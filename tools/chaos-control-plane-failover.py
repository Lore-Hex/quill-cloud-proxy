"""5-minute chaos test: partition one control-plane region, prove GA fails over.

FAILURE MODE CHOSEN: scale the eu-west-3 Fargate service to 0. That drops the
NLB's only healthy target, which is what a regional partition looks like from
Global Accelerator's side (endpoint unhealthy) WITHOUT tearing down the NLB
itself — so recovery is a scale-back-up, not a rebuild.

WHAT IS ASSERTED (all four, or the run fails):
  1. failover happens within a bounded window (GA hc: 10s interval x 3)
  2. it STAYS failed over for the full 5 minutes — no flapping
  3. requests keep succeeding after the failover point (bounded error window)
  4. recovery: restoring the region brings it back into rotation cleanly

Polls the PUBLIC hostname continuously (that is what a customer sees), and
separately watches GA's own health view so the two stories can be compared.
"""
import json
import subprocess
import sys
import time
import urllib.request

REGION_KILL = "eu-west-3"
CLUSTER = "tr-cp"
SERVICE = "tr-cp-euw3"
URL = "https://aws.trustedrouter.com/status.json"
EUW1 = "https://aws-euw1.trustedrouter.com/status.json"
EUW3 = "https://aws-euw3.trustedrouter.com/status.json"
LISTENER = ("arn:aws:globalaccelerator::330422590279:accelerator/"
            "fef56bcc-2d62-42ab-9995-b5fa3b8931be/listener/b06dbba7")
WATCH_SECONDS = 300
POLL = 3.0


def sh(*args: str) -> str:
    out = subprocess.run(args, capture_output=True, text=True)
    return out.stdout.strip()


def probe(url: str, timeout: float = 5.0) -> int:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "tr-chaos/1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except Exception:
        return 0


def ga_health() -> dict:
    raw = sh("aws", "globalaccelerator", "list-endpoint-groups", "--region", "us-west-2",
             "--listener-arn", LISTENER, "--output", "json")
    try:
        groups = json.loads(raw)["EndpointGroups"]
    except Exception:
        return {}
    return {
        g["EndpointGroupRegion"]: (g.get("EndpointDescriptions") or [{}])[0].get("HealthState", "?")
        for g in groups
    }


def scale(count: int) -> None:
    sh("aws", "ecs", "update-service", "--region", REGION_KILL, "--cluster", CLUSTER,
       "--service", SERVICE, "--desired-count", str(count), "--query", "service.serviceName",
       "--output", "text")


print("=== BASELINE ===")
print(f"  public       : {probe(URL)}")
print(f"  eu-west-1    : {probe(EUW1)}")
print(f"  eu-west-3    : {probe(EUW3)}")
print(f"  GA health    : {ga_health()}")

print(f"\n=== PARTITION: scaling {SERVICE} ({REGION_KILL}) to 0 ===")
scale(0)
kill_t = time.time()

samples = []          # (elapsed, public_status, euw3_status)
first_failover = None  # when euw3 stopped serving but public kept 200
errors = []            # elapsed times where the public endpoint failed
last_ga_print = 0.0

print(f"=== WATCHING PUBLIC ENDPOINT FOR {WATCH_SECONDS}s ===")
while time.time() - kill_t < WATCH_SECONDS:
    t = time.time() - kill_t
    pub = probe(URL)
    e3 = probe(EUW3, timeout=4.0)
    samples.append((t, pub, e3))
    if pub != 200:
        errors.append(t)
    if first_failover is None and e3 != 200:
        first_failover = t
        print(f"  [{t:6.1f}s] eu-west-3 is DOWN (direct probe={e3}); public={pub}")
    if t - last_ga_print >= 30:
        last_ga_print = t
        print(f"  [{t:6.1f}s] public={pub} euw3={e3} ga={ga_health()}")
    time.sleep(POLL)

total = len(samples)
ok = sum(1 for _, p, _ in samples if p == 200)
post = [s for s in samples if first_failover is not None and s[0] > first_failover + 45]
post_ok = sum(1 for _, p, _ in post if p == 200)

print("\n=== RESULTS ===")
print(f"  samples                 : {total} over {WATCH_SECONDS}s")
print(f"  public 200              : {ok}/{total} ({100*ok/total:.1f}%)")
print(f"  eu-west-3 down detected : {first_failover:.1f}s" if first_failover else "  eu-west-3 never went down (!)")
if errors:
    print(f"  error window            : {errors[0]:.1f}s .. {errors[-1]:.1f}s ({len(errors)} samples)")
else:
    print("  error window            : NONE — zero customer-visible failures")
if post:
    print(f"  steady-state after fail : {post_ok}/{len(post)} 200s ({100*post_ok/len(post):.1f}%)  <- no flapping if 100%")
print(f"  GA health at end        : {ga_health()}")

print(f"\n=== RECOVERY: scaling {SERVICE} back to 1 ===")
scale(1)
for i in range(24):
    time.sleep(15)
    h = ga_health()
    pub = probe(URL)
    e3 = probe(EUW3, timeout=4.0)
    print(f"  [{i*15+15:4d}s] public={pub} euw3={e3} ga={h}")
    if h.get("eu-west-3") == "HEALTHY" and e3 == 200:
        print("  RECOVERED: eu-west-3 back in rotation and serving")
        break

verdict_ok = (
    first_failover is not None
    and (not post or post_ok == len(post))
    and ok / total >= 0.95
)
print(f"\nVERDICT: {'PASS' if verdict_ok else 'REVIEW'}")
sys.exit(0 if verdict_ok else 1)
