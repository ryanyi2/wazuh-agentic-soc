"""FastAPI ingestion service.

The endpoint authenticates, validates, enqueues, and returns 202 in
milliseconds. A background worker runs the bounded agent loop, offloaded to a
thread so the event loop stays free.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request

from agentic_soc.agent.anthropic_client import AnthropicLLM
from agentic_soc.agent.llm import LLMClient
from agentic_soc.agent.loop import run_agent
from agentic_soc.agent.tools import Tool
from agentic_soc.agent.wazuh_tools import make_search_alerts_tool
from agentic_soc.auth import verify
from agentic_soc.clients.indexer import IndexerClient
from agentic_soc.config import Settings, get_settings
from agentic_soc.logging_config import configure_logging
from agentic_soc.models import Alert

logger = logging.getLogger(__name__)


def _build_default_tools(settings: Settings) -> dict[str, Tool]:
    if not settings.indexer_url:
        return {}
    indexer = IndexerClient(
        base_url=settings.indexer_url,
        user=settings.indexer_user,
        password=settings.indexer_password,
        verify_tls=settings.indexer_verify_tls,
    )
    return {"search_alerts": make_search_alerts_tool(indexer)}


async def _worker(queue: asyncio.Queue[Alert], llm: LLMClient, tools: dict[str, Tool]) -> None:
    while True:
        alert = await queue.get()
        try:
            verdict = await asyncio.to_thread(run_agent, alert, llm, tools)
            logger.info(
                "verdict rule=%s risk=%s confidence=%.2f summary=%s",
                alert.rule.id,
                verdict.risk_level.value,
                verdict.confidence,
                verdict.summary,
            )
        except Exception:
            logger.exception("agent failed for rule=%s", alert.rule.id)
        finally:
            queue.task_done()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    llm: LLMClient = app.state.llm or AnthropicLLM(
        api_key=settings.anthropic_api_key,
        model=settings.model,
        max_tokens=settings.max_tokens,
    )
    tools: dict[str, Tool] = app.state.tools
    if tools is None:
        tools = _build_default_tools(settings)
    queue: asyncio.Queue[Alert] = asyncio.Queue()
    app.state.queue = queue
    task = asyncio.create_task(_worker(queue, llm, tools))
    try:
        yield
    finally:
        task.cancel()


def create_app(
    settings: Settings | None = None,
    llm: LLMClient | None = None,
    tools: dict[str, Tool] | None = None,
) -> FastAPI:
    configure_logging()
    settings = settings or get_settings()
    app = FastAPI(title="Agentic SOC Analyst", lifespan=lifespan)
    app.state.settings = settings
    app.state.llm = llm
    app.state.tools = tools

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/alerts", status_code=202)
    async def ingest(request: Request, x_signature: str = Header(default="")) -> dict[str, str]:
        body = await request.body()
        if not verify(body, settings.hmac_secret, x_signature):
            raise HTTPException(status_code=401, detail="invalid signature")
        try:
            alert = Alert.model_validate_json(body)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid alert") from exc
        if alert.rule.level < settings.min_rule_level:
            return {"status": "skipped"}
        await request.app.state.queue.put(alert)
        return {"status": "accepted"}

    return app


app = create_app()
