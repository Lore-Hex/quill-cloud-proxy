"""Parent process FastAPI app.

Core endpoints:
  GET  /admin/usage          → operator-auth (basic, separate secret),
                               returns aggregate counters from DynamoDB
                               + in-flight from the enclave.
  GET  /trust                → public, server-rendered HTML showing the
                               attestation status, git commit, image
                               digest, schema, retention policy.
  GET  /health               → 200 only if the enclave vsock socket accepts
                               a connect; 503 otherwise (no body
                               inspection). This is what the NLB target
                               group checks, so it MUST reflect the enclave
                               and not merely this process.

FastAPI must not be the production inference listener. The production
path is raw TCP passthrough to the enclave-owned TLS terminator.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse

from quill_parent import bootstrap_server
from quill_parent.bootstrap_server import AF_VSOCK
from quill_parent.config import Settings, get_settings
from quill_parent.heartbeat import Heartbeat, emit_startup
from quill_parent.logging import configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    settings = get_settings()
    emit_startup(version="0.1.0", git_commit=settings.git_commit)

    heartbeat = Heartbeat(interval_seconds=settings.heartbeat_interval_seconds)
    import asyncio

    # Hold a strong ref to the heartbeat task so it isn't GC'd.
    app.state.heartbeat = heartbeat
    app.state.heartbeat_task = asyncio.create_task(heartbeat.run())

    # Bootstrap RPC: serve BootstrapData to the Go enclave on vsock 9100.
    # Only enabled in production (QUILL_BOOTSTRAP_SERVER=true); skipped
    # for tests + local dev where AF_VSOCK isn't available anyway.
    #
    # The new signature reflects the multi-provider direct-API path —
    # all provider keys come from AWS Secrets Manager at well-known
    # paths under `settings.secret_prefix` (default "quill/"), and the
    # cross-cloud GCP SA key is KMS-unwrapped via the alias in
    # `settings.gcp_sa_kms_alias`. No more bucket/object_key/bedrock
    # arguments — those are dead architecture (see V1.1 trust roadmap).
    bootstrap_task: asyncio.Task[None] | None = None
    if bootstrap_server.is_enabled():
        bootstrap_task = asyncio.create_task(
            bootstrap_server.serve_forever(
                region=settings.aws_region,
                secret_prefix=settings.secret_prefix,
                gcp_sa_kms_alias=settings.gcp_sa_kms_alias,
                tr_control_plane_base_url=settings.tr_control_plane_base_url,
            )
        )
        app.state.bootstrap_task = bootstrap_task

    # The TCP pump (NLB :8444 → enclave vsock 16:8001) used to live in
    # this process as `tcp_relay.serve_forever()`. It's now a dedicated
    # Go binary — enclave-go/cmd/parent-pump — running in a separate
    # container on the host. The Python parent only handles the control
    # plane (/admin/usage, /trust, /health) and the bootstrap RPC
    # server. The pump's data path is latency-sensitive enough to be
    # worth a Go rewrite (no GIL, io.Copy between two net.Conns).

    try:
        yield
    finally:
        app.state.heartbeat_task.cancel()
        if bootstrap_task is not None:
            bootstrap_task.cancel()


def create_app() -> FastAPI:
    app = FastAPI(
        title="quill-cloud-proxy (parent)",
        description="Outside-the-enclave host process. Open source.",
        lifespan=lifespan,
    )
    app.include_router(_make_router())
    return app


def _make_router() -> APIRouter:
    router = APIRouter()

    @router.get("/health")
    async def health(
        response: Response,
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> dict[str, str]:
        """Report whether the ENCLAVE is reachable, not whether this process is.

        This endpoint is what the NLB target group health-checks
        (tools/deploy-aws-nitro.sh: HCProtocol=HTTP HCPort=8443
        HCPath=/health), and it used to return {"status": "ok"}
        unconditionally — while the module docstring claimed it connected to
        the enclave socket. So a host whose enclave had died stayed
        "healthy" and kept taking traffic, and any failover built on top of
        it (Global Accelerator, a second region) inherited the lie.

        A vsock connect is the cheapest signal that actually distinguishes
        "the enclave is listening" from "the Python container is up". It
        does NOT prove the attestation path works — that is the synthetic
        monitor's job, once a minute, against /attestation.
        """
        if await _enclave_is_reachable(settings):
            return {"status": "ok"}
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "enclave_unreachable"}

    @router.get("/admin/usage")
    async def admin_usage(
        request: Request,
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> JSONResponse:
        from quill_parent.admin import build_usage_report, check_admin_auth

        if not check_admin_auth(request, settings):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="admin auth required",
                headers={"WWW-Authenticate": 'Basic realm="quill-admin"'},
            )
        report = await build_usage_report(settings)
        return JSONResponse(report)

    @router.get("/trust", response_class=HTMLResponse)
    async def trust_page(
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> HTMLResponse:
        from quill_parent.trust import render_trust_page

        html = render_trust_page(settings)
        return HTMLResponse(html, headers={"cache-control": "max-age=60"})

    return router


app = create_app()


async def _enclave_is_reachable(settings: Settings) -> bool:
    """Can we open a vsock connection to the enclave right now?

    Runs in a thread so a slow or blackholed dial cannot stall the event
    loop that is also serving inference. Any failure is unhealthy: this is
    a health check, and "I could not tell" must never read as "fine" —
    that equivalence is what made the previous version useless.
    """

    def dial() -> bool:
        sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        try:
            sock.settimeout(settings.enclave_health_timeout_seconds)
            sock.connect((settings.enclave_cid, settings.enclave_relay_port))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(dial),
            timeout=settings.enclave_health_timeout_seconds + 0.5,
        )
    except (TimeoutError, OSError):
        return False
