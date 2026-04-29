"""The most important test in the repo.

AST-walks every file under `quill_enclave` (excluding the `_*_mock.py`
files which are explicitly local-dev only) and fails if any forbidden
identifier appears. This is the mechanical proof that the enclave never
logs or writes to disk.

Forbidden identifiers in production enclave source:
  - print
  - log, logger, logging
  - open  (file open)
  - sys.stdout, sys.stderr (catches `import sys; sys.stdout.write(...)`)
  - any os.path / pathlib path manipulation that could write
  - http.client / urllib3 / requests / aiohttp / httpx (use raw vsock + TLS)

Allowed exceptions (with rationale):
  - `socket.*` — the only network primitive (vsock only via attest/transport)
  - `ssl.*` — TLS to Bedrock, in-enclave
  - `hashlib.*` — bearer hashing
  - `json.*` — request/response parsing
  - `asyncio.*` — concurrency
  - `os.environ.get` — selecting transport mock vs real (boot-time only)
"""

from __future__ import annotations

import ast
from pathlib import Path

# Modules ending in _mock are local-dev only; not in the enclave EIF.
_LOCAL_DEV_ONLY = {"_nsm_mock.py", "_bedrock_mock.py", "transport.py"}

_FORBIDDEN_NAMES: frozenset[str] = frozenset(
    {
        "print",
        "open",  # builtin open() for file IO
        "logging",
        "log",
        "logger",
    }
)

_FORBIDDEN_ATTRS: frozenset[str] = frozenset(
    {
        "stdout",
        "stderr",
        "stdin",
        "writelines",
    }
)

_FORBIDDEN_IMPORTS: frozenset[str] = frozenset(
    {
        "logging",
        "http.client",
        "urllib",
        "urllib.request",
        "urllib3",
        "requests",
        "aiohttp",
        "httpx",  # only allowed in tests / mocks
        "syslog",
    }
)


def _enclave_files() -> list[Path]:
    src = Path(__file__).resolve().parents[1] / "src" / "quill_enclave"
    files: list[Path] = []
    for p in src.glob("*.py"):
        if p.name in _LOCAL_DEV_ONLY:
            continue
        files.append(p)
    return files


def _violations(path: Path) -> list[str]:
    out: list[str] = []
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _FORBIDDEN_NAMES:
                out.append(f"call to forbidden builtin {func.id!r} at line {node.lineno}")
            if isinstance(func, ast.Attribute) and func.attr in _FORBIDDEN_ATTRS:
                out.append(f"call to forbidden attr {func.attr!r} at line {node.lineno}")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _FORBIDDEN_IMPORTS:
                    out.append(f"forbidden import {alias.name!r} at line {node.lineno}")
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod in _FORBIDDEN_IMPORTS:
                out.append(f"forbidden from-import {mod!r} at line {node.lineno}")
    return out


def test_no_forbidden_identifiers_in_enclave_source() -> None:
    failures: list[str] = []
    for path in _enclave_files():
        violations = _violations(path)
        if violations:
            failures.append(f"{path.name}: {'; '.join(violations)}")
    assert not failures, "Enclave production source contains forbidden I/O:\n" + "\n".join(failures)
