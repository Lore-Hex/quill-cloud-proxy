"""AST scan parent source for forbidden log fields.

Asserts that no `log.<level>(...)` call passes any of the forbidden
keyword arguments. The redactor in `logging.py` is belt-and-suspenders;
this test prevents anyone from accidentally introducing the leak.
"""

from __future__ import annotations

import ast
from pathlib import Path

_FORBIDDEN_KWARGS: frozenset[str] = frozenset(
    {
        "messages",
        "content",
        "prompt",
        "completion",
        "text",
        "delta",
        "key",
        "authorization",
        "body",
        "payload",
        "bearer",
    }
)

_LOG_METHODS: frozenset[str] = frozenset(
    {"debug", "info", "warning", "warn", "error", "critical", "exception"}
)


def _violations(path: Path) -> list[str]:
    out: list[str] = []
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in _LOG_METHODS:
            continue
        # Treat any Attribute call whose method is debug/info/etc as a log call.
        for kw in node.keywords:
            if kw.arg and kw.arg in _FORBIDDEN_KWARGS:
                out.append(f"log call passes forbidden kwarg {kw.arg!r} at line {node.lineno}")
    return out


def test_no_forbidden_kwargs_in_log_calls() -> None:
    src = Path(__file__).resolve().parents[1] / "src" / "quill_parent"
    failures: list[str] = []
    for path in src.glob("*.py"):
        violations = _violations(path)
        if violations:
            failures.append(f"{path.name}: {'; '.join(violations)}")
    assert not failures, "Parent source has log calls with forbidden fields:\n" + "\n".join(
        failures
    )
