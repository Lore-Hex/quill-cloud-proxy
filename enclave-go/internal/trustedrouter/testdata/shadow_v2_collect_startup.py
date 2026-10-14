"""Join Go startup output to the read-only sibling collector with fake inputs.

Usage: python shadow_v2_collect_startup.py SIBLING_SRC PRODUCER_JSON OUTPUT_DIR
The Go producer is TestStartupSharedReleaseOriginal with STARTUP_COLLECTOR_OUTPUT.
"""
import copy
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, sys.argv[1])
from trusted_router.async_settle_shadow_v2_collect_ports import (Files, Pass, Page, Query, day_bounds, resolve_emitted_reference)
from trusted_router.async_settle_shadow_v2_collect_inventory import InventoryResult
from trusted_router.async_settle_shadow_v2_collect_readiness import collect
from trusted_router.detached_jws import canonical

payload = json.loads(pathlib.Path(sys.argv[2]).read_bytes())
files = Files(pathlib.Path(sys.argv[3]))
original = payload['config_original'].encode()
literal = pathlib.Path(__file__).with_name('shadow_v2_shared_release_config.json').read_bytes()
assert original == literal
config = files.put('release/config.json', original)
assert config['sha256'] == hashlib.sha256(literal).hexdigest()
manifest = payload['manifest']
# Policy and fixture bytes are external release inputs. This join test uses
# explicit fake originals and updates those two unrelated pins consistently.
policy = files.put('release/policy.json', b'{}')
fixture = files.put('release/fixture.json', b'[]')
records = copy.deepcopy(payload['records'])
index = {}
for record in records:
    refs = []
    if 'clock_basis' in record:
        refs.append(('clock_basis.original', record['clock_basis'], 'original'))
    for key in ('public_descriptors', 'attested_image'):
        if key in record:
            refs.append((key, record, key))
    for field, owner, key in refs:
        coordinate = owner[key]
        raw = canonical(payload['originals'][coordinate['sha256']])
        ref = files.put('originals/' + coordinate['sha256'] + '.json', raw)
        index[(coordinate['kind'], ref['sha256'], ref['bytes'])] = ref
        owner[key] = resolve_emitted_reference(files, field, coordinate, index)
    if record.get('criterion') == 'marker_keys':
        record['policy_sha256'], record['fixture_sha256'] = policy['sha256'], fixture['sha256']
checks = [r for r in records if r['kind'] == 'a3_boot_check']
assert len(checks) == 6 and all(r['config_sha256'] == config['sha256'] for r in checks)
base = checks[0]
boot = {key: base[key] for key in ('boot', 'role', 'revision', 'region', 'boot_at_us')}
start, end = day_bounds('2023-11-14')
boot.update(start_us=start, end_us=end, pins=next(r['effective_pins'] for r in checks if r['criterion'] == 'marker_keys'))
artifacts = []
for sources in manifest['artifacts'].values():
    for a in sources.values():
        a = dict(a)
        a.update(router_revision='e'*40, enclave_revision=boot['revision'], conclusion='pass')
        a['original'] = files.obj('trials/' + a['id'] + '.json', {'fake_trial': a['id']})
        if a['source'] == 'budget_trial':
            a.update(workspace_count=1, within_envelope=True)
        artifacts.append(a)

class Capture:
    def __init__(self, values):
        self.values = values
    def read(self, query, token):
        assert token is None
        return Page(canonical({'records': self.values}), None, True, 1, end)

pins = dict(config=config, policy=policy, fixture=fixture, router_revision='e'*40, enclave_revision=boot['revision'])
inventory = InventoryResult(None, {}, {}, (boot,), (), True)
run = Pass(files)
result = collect(run, inventory=inventory, ci=Capture(artifacts), logs=Capture([r for r in records if r['kind'] != 'a3_startup_correlation']), artifact_query=Query('ci', 'fake-ci', '2023-11-14', 100), startup_query=Query('startup', 'fake-startup', '2023-11-14', 100), pins=pins)
assert result.complete, run.missing
assert len(result.ledgers) == 1 and len(result.proofs) == 6
ledger = json.loads(files.read(result.ledgers[0]))
assert ledger['config_sha256'] == config['sha256']
print('shared-release-producer-to-collector PASS')
