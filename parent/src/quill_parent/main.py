"""Parent process FastAPI app.

Core endpoints:
  GET  /admin/usage          → operator-auth (basic, separate secret),
                               returns aggregate counters from DynamoDB
                               + in-flight from the enclave.
  GET  /trust                → public, server-rendered HTML showing the
                               attestation status, git commit, image
                               digest, schema, retention policy.
  GET  /health               → 200 if the enclave socket accepts a
                               connect (no body inspection).

FastAPI must not be the production inference listener. The production
path is raw TCP passthrough to the enclave-owned TLS terminator.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse

from quill_parent import bootstrap_server
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
    async def health() -> dict[str, str]:
        return {"status": "ok"}

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
