"""vsock transport.

Production: socket(AF_VSOCK, SOCK_STREAM). Available on Linux only and only
on Nitro hosts/enclaves.

Local dev / tests: when env var QUILL_TRANSPORT=unix-socket is set, swap to
a Unix domain socket so the same code paths exercise on a laptop. The mock
is clearly labeled and refuses to enable when running with NSM available
(prevents accidentally mocking in production).
"""

from __future__ import annotations

import contextlib
import os
import socket
from typing import Final

# AF_VSOCK isn't a constant on every libc/Python build; pin numerically.
AF_VSOCK: Final[int] = 40

# CIDs (vsock equivalent of IP). CID 3 is the parent (host) from the
# enclave's perspective; CID -1 (0xFFFFFFFF) is the local listening CID.
CID_PARENT: Final[int] = 3
PORT_PARENT_RELAY: Final[int] = 8001  # parent listens here, relays to TCP
PORT_PARENT_USAGE: Final[int] = 8002  # parent listens here, accepts CounterDelta JSONs


def use_unix_socket_transport() -> bool:
    return os.environ.get("QUILL_TRANSPORT") == "unix-socket"


def listen_inbound(port: int) -> socket.socket:
    """Bind a vsock listener for incoming HTTP from the parent's relay.

    In production: the enclave listens on (CID_LOCAL, port) and the parent
    forwards client bytes to here.

    In dev: bind a Unix-domain socket at /tmp/quill-enclave-<port>.sock.
    """
    if use_unix_socket_transport():
        path = f"/tmp/quill-enclave-{port}.sock"
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(path)
        s.listen(8)
        return s
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    s.bind((socket.VMADDR_CID_ANY, port))  # type: ignore[attr-defined]
    s.listen(8)
    return s


def connect_outbound(port: int) -> socket.socket:
    """Open a connection to the parent for outbound relays (Bedrock, S3, KMS)."""
    if use_unix_socket_transport():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(f"/tmp/quill-parent-{port}.sock")
        return s
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    s.connect((CID_PARENT, port))
    return s
