"""Artifact retrieval routes."""

from __future__ import annotations

import math
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.artifact import Artifact
from app.schemas.artifact import ArtifactRead, ArtifactSummary
from app.schemas.common import PaginatedResponse

router = APIRouter(prefix="/artifacts", tags=["artifacts"])


@router.get("", response_model=PaginatedResponse[ArtifactSummary])
async def list_artifacts(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
) -> PaginatedResponse[ArtifactSummary]:
    count_q = select(func.count()).select_from(Artifact)
    total = (await session.execute(count_q)).scalar_one()

    offset = (page - 1) * per_page
    items_q = (
        select(Artifact)
        .order_by(Artifact.priority_score.desc().nullslast(), Artifact.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await session.execute(items_q)
    items = list(result.scalars().all())

    return PaginatedResponse(
        items=[ArtifactSummary.model_validate(i) for i in items],
        total=total,
        page=page,
        per_page=per_page,
        total_pages=max(1, math.ceil(total / per_page)),
    )


@router.get("/{artifact_id}", response_model=ArtifactRead)
async def get_artifact(
    artifact_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ArtifactRead:
    artifact = await session.get(Artifact, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return ArtifactRead.model_validate(artifact)
