#!/usr/bin/env python3
"""Move a duplicate provider key assignment to an inert standby name, in place."""

import argparse
import contextlib
import fcntl
import os
import re
import stat
import tempfile
from pathlib import Path


def staged(data: bytes, name: str) -> tuple[bytes, bool]:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*_API_KEY", name):
        raise ValueError("expected a provider API key variable name")
    key = name.encode("ascii")
    standby = key + b"_STANDBY"
    pattern = re.compile(rb"^([ \t]*(?:export[ \t]+)?)(" + key + rb"(?:_STANDBY)?)([ \t]*=)(.*)$")
    lines = data.splitlines(keepends=True)
    entries = []
    for i, line in enumerate(lines):
        match = pattern.match(line.rstrip(b"\r\n"))
        if match:
            value = match[4].strip()
            if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in (b"'", b'"'):
                value = value[1:-1]
            if not value or any(chr(c).isspace() for c in value) or b"#" in value:
                raise ValueError("empty or ambiguous credential assignment; no change")
            entries.append((i, match, value))
    if len(entries) != 2 or entries[0][1][2] != key or entries[0][2] == entries[1][2]:
        raise ValueError("expected distinct primary and standby entries, in order; no change")
    i, match, _ = entries[1]
    if match[2] == standby:
        return data, False
    start, end = match.span(2)
    lines[i] = lines[i][:start] + standby + lines[i][end:]
    return b"".join(lines), True


def stage(path: Path, name: str) -> bool:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as original:
        fcntl.flock(original, fcntl.LOCK_EX)
        st = os.fstat(original.fileno())
        if (not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_uid != os.getuid() or st.st_nlink != 1):
            raise ValueError("key file must be a private, singly linked, owner-held regular file")
        data, changed = staged(original.read(), name)
        if not changed:
            return False
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".stage-key-")
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            now = path.lstat()
            if not os.path.samestat(st, now) or (st.st_size, st.st_ctime_ns) != (now.st_size, now.st_ctime_ns):
                raise ValueError("key file changed during staging; no change")
            os.replace(tmp, path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name")
    parser.add_argument("--key-file", type=Path, default=Path.home() / ".quill_cloud_keys.private")
    args = parser.parse_args()
    try:
        print("Standby staged; primary unchanged." if stage(args.key_file, args.name) else "Already staged.")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Cannot stage standby: {exc}\n")
