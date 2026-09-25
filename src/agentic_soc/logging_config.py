"""Logging setup for the service.

Python's default threshold is WARNING, so INFO messages (like the worker
reporting a dequeued alert) are dropped unless logging is configured. This wires
the package logger to emit INFO to stdout without disturbing uvicorn's loggers.
"""

from __future__ import annotations

import logging

_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


def configure_logging(level: int = logging.INFO) -> None:
    logger = logging.getLogger("agentic_soc")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(_FORMAT))
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
