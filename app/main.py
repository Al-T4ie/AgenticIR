"""FastAPI entrypoint."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.api import routes, slack_routes, ui_routes
from app.config import get_settings
from app.db.session import close_db, init_db
from app.graph.builder import close_graph, init_graph
from app.observability import configure_logging, configure_tracing, get_logger
from app.services import runner, upkeep
from app.slack import poller

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    configure_tracing()
    settings = get_settings()

    log.info(
        "startup",
        env=settings.app_env,
        llm_provider=settings.llm_provider,
        slack=settings.slack_enabled,
        slack_poll=settings.slack_poll_enabled,
        upkeep=settings.upkeep_enabled,
        n8n=settings.n8n_enabled,
    )

    await init_db()
    await init_graph()
    app.state.ready = True

    try:
        recovered = await runner.recover_interrupted()
        if recovered:
            log.info("startup.recovered_runs", count=recovered)
    except Exception as exc:
        # Recovery is best-effort: never block startup on it, or one poisoned
        # checkpoint takes the whole service down.
        log.error("startup.recovery_failed", error=str(exc))

    poller.start()
    upkeep.start()

    try:
        yield
    finally:
        app.state.ready = False
        await poller.stop()
        await upkeep.stop()
        await runner.drain(timeout=25.0)
        await close_graph()
        await close_db()
        log.info("shutdown.complete")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="AgenticIR",
        description="Self-hosted agentic incident response platform",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    app.state.ready = False

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    app.include_router(routes.router)
    app.include_router(slack_routes.router)
    app.include_router(ui_routes.router)

    @app.get("/", include_in_schema=False)
    async def root() -> Any:
        return RedirectResponse("/ui")

    @app.get("/health", tags=["ops"], summary="Liveness")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "agentic-ir", "version": "0.1.0"}

    @app.get("/ready", tags=["ops"], summary="Readiness")
    async def ready() -> Any:
        """Distinct from /health: this reports whether dependencies are wired up.

        Coolify's healthcheck points here so a container with a dead database
        never receives traffic.
        """
        if not app.state.ready:
            return JSONResponse({"status": "starting"}, status_code=503)
        try:
            from sqlalchemy import text

            from app.db.session import session_scope

            async with session_scope() as session:
                await session.execute(text("SELECT 1"))
        except Exception as exc:
            log.warning("ready.db_check_failed", error=str(exc))
            return JSONResponse({"status": "degraded", "detail": str(exc)}, status_code=503)
        return {"status": "ready"}

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",  # noqa: S104 — bound inside the container network only
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("APP_ENV", "development") == "development",
    )
