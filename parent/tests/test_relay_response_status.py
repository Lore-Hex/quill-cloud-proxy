from __future__ import annotations

from quill_parent.relay import _build_http_request, _parse_content_type, _parse_status_code


def test_parse_status_code() -> None:
    assert _parse_status_code(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json") == 401


def test_parse_status_code_falls_back_to_bad_gateway() -> None:
    assert _parse_status_code(b"not-http") == 502


def test_parse_content_type() -> None:
    assert (
        _parse_content_type(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n")
        == "application/json"
    )


def test_build_http_request_preserves_route_path_and_body_bytes() -> None:
    body = b'{"input":"opaque"}'
    wrapped = _build_http_request(body, "Bearer sk-test", "/v1/responses")
    assert wrapped.startswith(b"POST /v1/responses HTTP/1.1\r\n")
    assert wrapped.endswith(body)
    assert b"Authorization: Bearer sk-test\r\n" in wrapped


def test_build_http_request_preserves_method_for_responses_subroutes() -> None:
    wrapped = _build_http_request(
        b"",
        "Bearer sk-test",
        "/v1/responses/resp_123/input_items?limit=1",
        method="GET",
    )
    assert wrapped.startswith(b"GET /v1/responses/resp_123/input_items?limit=1 HTTP/1.1\r\n")
    assert b"Content-Length: 0\r\n" in wrapped
