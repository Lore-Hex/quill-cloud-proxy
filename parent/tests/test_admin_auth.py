from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from fastapi import Request

from quill_parent.admin import check_admin_auth
from quill_parent.config import Settings


def _sha1_b64(s: str) -> str:
    return base64.b64encode(hashlib.sha1(s.encode("utf-8"), usedforsecurity=False).digest()).decode(
        "ascii"
    )


def _settings(htpasswd: Path) -> Settings:
    return Settings(admin_htpasswd_path=htpasswd)


def _make_request(authorization: str | None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode("ascii")))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/admin/usage",
        "headers": headers,
        "client": ("10.0.0.5", 0),
    }
    return Request(scope)


def test_no_auth_rejected(tmp_path: Path) -> None:
    htp = tmp_path / "htpasswd"
    htp.write_text(f"admin:{{SHA}}{_sha1_b64('hunter2')}\n")
    assert check_admin_auth(_make_request(None), _settings(htp)) is False


def test_wrong_password_rejected(tmp_path: Path) -> None:
    htp = tmp_path / "htpasswd"
    htp.write_text(f"admin:{{SHA}}{_sha1_b64('hunter2')}\n")
    auth = "Basic " + base64.b64encode(b"admin:wrong").decode("ascii")
    assert check_admin_auth(_make_request(auth), _settings(htp)) is False


def test_correct_password_allowed(tmp_path: Path) -> None:
    htp = tmp_path / "htpasswd"
    htp.write_text(f"admin:{{SHA}}{_sha1_b64('hunter2')}\n")
    auth = "Basic " + base64.b64encode(b"admin:hunter2").decode("ascii")
    assert check_admin_auth(_make_request(auth), _settings(htp)) is True
