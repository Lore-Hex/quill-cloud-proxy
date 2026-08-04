"""/health must report the ENCLAVE, not this process.

The NLB target group health-checks this endpoint. It used to return
{"status": "ok"} unconditionally while the module docstring claimed it
connected to the enclave socket — so a host whose enclave had died stayed
"healthy" and kept taking traffic, and any failover built on top of it
(Global Accelerator, a second region) inherited the lie.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from quill_parent import main as main_module
from quill_parent.config import Settings


def _client(monkeypatch: pytest.MonkeyPatch, reachable: bool | Exception) -> TestClient:
    async def fake_reachable(_settings: Settings) -> bool:
        if isinstance(reachable, Exception):
            raise reachable
        return reachable

    monkeypatch.setattr(main_module, "_enclave_is_reachable", fake_reachable)
    return TestClient(main_module.create_app(), raise_server_exceptions=False)


def test_healthy_when_enclave_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _client(monkeypatch, True).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_unhealthy_when_enclave_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    """The regression that matters: a dead enclave must eject the host."""
    response = _client(monkeypatch, False).get("/health")
    assert response.status_code == 503
    assert response.json()["status"] == "enclave_unreachable"


def test_dial_failure_is_unhealthy_not_healthy() -> None:
    """'I could not tell' must never read as 'fine'. That equivalence is
    what made the previous version useless."""
    import asyncio

    settings = Settings(enclave_cid=0xFFFFFFFE, enclave_health_timeout_seconds=0.2)
    assert asyncio.run(main_module._enclave_is_reachable(settings)) is False


def test_health_timeout_stays_under_target_group_budget() -> None:
    """The NLB check times out at 5s. A dial budget at or above that turns
    a slow enclave into a flapping target instead of a clean unhealthy."""
    assert Settings().enclave_health_timeout_seconds < 5.0
