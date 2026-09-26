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
    if settings.is_production:
        if not settings.secret_key or settings.secret_key == "change-me":
            raise RuntimeError("SECRET_KEY must be set to a strong value in production")
        if settings.debug:
            raise RuntimeError("DEBUG must be false in production")
        if "*" in settings.cors_origin_list:
            raise RuntimeError("CORS_ORIGINS must not contain '*' in production")
    logger.info(
        "mce.startup",
        app_name=settings.app_name,
        environment=settings.app_env,
        debug=settings.debug,
    )
    # The repository does not yet contain an Alembic revision. Create the
    # schema at startup so a fresh single-instance deployment is usable.
    # Replace this bootstrap with `alembic upgrade head` once migrations are
    # introduced; startup schema creation is not suitable for multi-instance
    # zero-downtime migrations.
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
        docs_url=None if settings.is_production else "/api/docs",
        redoc_url=None if settings.is_production else "/api/redoc",
        openapi_url=None if settings.is_production else "/api/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
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

