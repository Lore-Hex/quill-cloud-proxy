from __future__ import annotations

from quill_parent.heartbeat import Heartbeat


def test_record_drains_to_zero() -> None:
    hb = Heartbeat(interval_seconds=3600)
    hb.record(ok=True)
    hb.record(ok=True)
    hb.record(ok=False)
    req, err = hb._drain()
    assert req == 3
    assert err == 1
    req, err = hb._drain()
    assert req == 0 and err == 0
