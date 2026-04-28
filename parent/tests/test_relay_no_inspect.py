"""Static analysis: the relay function must not parse the body.

Greps relay.py for any json.loads / eval / serializers and fails. The
relay is allowed to:
  - read raw bytes
  - write raw bytes
  - call socket primitives
  - construct a static HTTP-request prefix from a header dict containing
    only `bearer`, `Host`, `Content-Type`, `Content-Length`, `Connection`.
"""

from __future__ import annotations

import ast
from pathlib import Path

_FORBIDDEN_NAMES: frozenset[str] = frozenset(
    {
        "loads",  # json.loads (or any .loads variant)
        "load",  # json.load
        "decode",  # bytes.decode is OK on header dict but suspicious in body context
        "eval",
        "exec",
    }
)


def test_relay_does_not_parse_body() -> None:
    relay = Path(__file__).resolve().parents[1] / "src" / "quill_parent" / "relay.py"
    src = relay.read_text(encoding="utf-8")
    tree = ast.parse(src)
    # Allow header-construction calls to .encode/.decode on a fixed string,
    # but flag anything calling .loads/.load/.eval/.exec.
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in {"loads", "load", "eval", "exec"}:
                findings.append(f"forbidden parse-call .{func.attr}() at line {node.lineno}")
            if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
                findings.append(f"forbidden builtin {func.id}() at line {node.lineno}")
    assert not findings, "Relay does body inspection:\n" + "\n".join(findings)
