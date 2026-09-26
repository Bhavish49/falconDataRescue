"""falconDataRescue Forensic Recovery Platform — FastAPI application entry point."""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.db.base import Base
from app.db.session import engine

# Import all models so Base.metadata is fully populated
import app.models  # noqa: F401

from app.api.router import api_router

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application startup / shutdown hooks."""
    settings = get_settings()
    logger.info(
        "mce.startup",
        app_name=settings.app_name,
        environment=settings.app_env,
        debug=settings.debug,
    )
    # There are no checked-in Alembic revisions yet. Create the local
    # development schema automatically; production should use migrations.
    if not settings.is_production and settings.database_url.startswith("sqlite"):
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
    yield
    logger.info("mce.shutdown")


def create_app() -> FastAPI:
    """Application factory."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        description=(
            "AI-powered forensic file recovery platform. "
            "Analyzes disk images, parses MFT records, carves fragments, "
            "and uses ML to reassemble deleted files."
        ),
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # CORS — allow all origins in dev, lock down in production
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API
    app.include_router(api_router)

    # Mount Frontend Web UI (if frontend folder exists)
    from pathlib import Path
    from fastapi.staticfiles import StaticFiles

    frontend_path = Path(__file__).resolve().parent.parent.parent / "frontend"
    if frontend_path.exists():
        app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")

    return app


app = create_app()

