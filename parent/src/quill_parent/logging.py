"""Structlog setup for the parent process.

Strict policy: parent only emits the hourly heartbeat and a few
service-lifecycle events (startup, shutdown). It must never emit log
records that include any of these forbidden keys (test enforces):
  messages, content, prompt, completion, text, delta, key, authorization,
  body, payload, bearer.

The redactor processor is belt-and-suspenders — even if a future
contributor accidentally calls log.info("...", body=req_body), the
redactor replaces the value with "<redacted>". Tests scan the source for
log calls passing those keys and fail.
"""

from __future__ import annotations

import logging
from typing import Any, cast

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

_FORBIDDEN_KEYS: frozenset[str] = frozenset(
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


def _redact_forbidden(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
    for forbidden in _FORBIDDEN_KEYS:
        if forbidden in event_dict:
            event_dict[forbidden] = "<redacted>"
    return event_dict


def configure_logging() -> None:
    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        _redact_forbidden,  # MUST run before the renderer
        structlog.processors.StackInfoRenderer(),
        structlog.dev.ConsoleRenderer(colors=False),
    ]
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:  # noqa: ANN401  -- structlog typing limitation
    return cast("Any", structlog.get_logger(name))
