"""Root API router — aggregates all sub-routers under /api."""

from fastapi import APIRouter

from app.api.routes.health import router as health_router
from app.api.routes.repair import router as repair_router
from app.api.routes.pytsk3_routes import router as pytsk3_router
from app.api.routes.ai_routes import router as ai_router
from app.api.routes.evidence import router as evidence_router
from app.api.routes.scans import router as scans_router
from app.api.routes.artifacts import router as artifacts_router
from app.api.routes.deleted_routes import router as deleted_router

api_router = APIRouter(prefix="/api")

api_router.include_router(health_router)
api_router.include_router(repair_router)
api_router.include_router(pytsk3_router)
api_router.include_router(ai_router)
api_router.include_router(evidence_router)
api_router.include_router(scans_router)
api_router.include_router(artifacts_router)
api_router.include_router(deleted_router)



