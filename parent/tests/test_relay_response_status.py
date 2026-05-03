from __future__ import annotations

from quill_parent.relay import _parse_status_code


def test_parse_status_code() -> None:
    assert _parse_status_code(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json") == 401


def test_parse_status_code_falls_back_to_bad_gateway() -> None:
    assert _parse_status_code(b"not-http") == 502
