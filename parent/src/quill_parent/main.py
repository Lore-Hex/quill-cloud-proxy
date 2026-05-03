"""Parent process FastAPI app.

Three endpoints:
  POST /v1/chat/completions  → relay client bytes to the enclave verbatim,
                               stream the response back. Parent never
                               inspects the body.
  GET  /admin/usage          → operator-auth (basic, separate secret),
                               returns aggregate counters from DynamoDB
                               + in-flight from the enclave.
  GET  /trust                → public, server-rendered HTML showing the
                               attestation status, git commit, image
                               digest, schema, retention policy.
  GET  /health               → 200 if the enclave socket accepts a
                               connect (no body inspection).

We do NOT terminate TLS in FastAPI here — the ALB does. From the ALB the
parent listens HTTP on :8443 inside the VPC; the ALB-to-parent hop is
in-VPC.

Note on file structure: the relay path is intentionally a dumb byte pump.
We do not parse the request to make any auth decisions; the enclave
handles auth. This keeps the parent's view of payload bytes opaque.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from quill_parent import bootstrap_server, tcp_relay
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

    # Bootstrap RPC: serve BootstrapData to the Go enclave on vsock 9000.
    # Only enabled in production (QUILL_BOOTSTRAP_SERVER=true); skipped for
    # tests + local dev where AF_VSOCK isn't available anyway.
    bootstrap_task: asyncio.Task[None] | None = None
    if bootstrap_server.is_enabled():
        bootstrap_task = asyncio.create_task(
            bootstrap_server.serve_forever(
                bucket=settings.device_keys_bucket,
                object_key=settings.device_keys_object_key,
                region=settings.aws_region,
                bedrock_vsock_proxy=settings.bedrock_vsock_proxy,
                openrouter_secret_id=settings.openrouter_secret_id,
                openrouter_vsock_proxy=settings.openrouter_vsock_proxy,
            )
        )
        app.state.bootstrap_task = bootstrap_task

    # Phase 2 of TLS-inside: raw TCP pump from the NLB to the enclave's
    # vsock listener. Off by default until the enclave's QUILL_ENCLAVE_TLS
    # is also flipped on. Both can run simultaneously while the load-
    # balancer side is being switched from ALB → NLB.
    tcp_pump_task: asyncio.Task[None] | None = None
    if tcp_relay.is_enabled():
        tcp_pump_task = asyncio.create_task(tcp_relay.serve_forever(settings))
        app.state.tcp_pump_task = tcp_pump_task

    try:
        yield
    finally:
        app.state.heartbeat_task.cancel()
        if bootstrap_task is not None:
            bootstrap_task.cancel()
        if tcp_pump_task is not None:
            tcp_pump_task.cancel()


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

    async def read_limited_body(request: Request, limit: int) -> bytes:
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > limit:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail={
                        "error": {
                            "message": "request body too large",
                            "type": "request_too_large",
                        }
                    },
                )
            body.extend(chunk)
        return bytes(body)

    @router.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @router.post("/v1/chat/completions")
    async def chat_completions(
        request: Request,
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> StreamingResponse:
        # The parent does NOT parse, validate, or inspect the body. It opens
        # a socket to the enclave, forwards request bytes verbatim, and
        # streams the response bytes back to the client. Auth happens
        # inside the enclave.
        from quill_parent.relay import relay_to_enclave_response

        body = await read_limited_body(request, settings.max_request_body_bytes)
        bearer = request.headers.get("authorization", "")
        # Forward only the bearer header + body to the enclave (it builds
        # its own response). The enclave doesn't need any other header.
        relay = await relay_to_enclave_response(
            body=body, bearer=bearer, settings=settings, heartbeat=request.app.state.heartbeat
        )
        media_type = "text/event-stream" if relay.status_code == 200 else "application/json"
        return StreamingResponse(
            relay.chunks,
            status_code=relay.status_code,
            media_type=media_type,
            headers={"cache-control": "no-cache", "x-accel-buffering": "no"},
        )

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
