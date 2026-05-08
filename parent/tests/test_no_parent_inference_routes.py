from __future__ import annotations

from pathlib import Path

from quill_parent.main import create_app


def test_parent_has_no_http_inference_routes() -> None:
    app = create_app()
    paths = {getattr(route, "path", "") for route in app.routes}

    assert "/v1/chat/completions" not in paths
    assert "/v1/responses" not in paths
    assert not any(path.startswith("/v1/") for path in paths)


def test_legacy_http_relay_module_is_removed() -> None:
    relay_path = Path(__file__).resolve().parents[1] / "src" / "quill_parent" / "relay.py"
    assert not relay_path.exists()
