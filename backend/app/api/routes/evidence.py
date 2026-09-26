"""Evidence CRUD routes."""

from __future__ import annotations

import math
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.schemas.common import PaginatedResponse
from app.schemas.evidence import (
    EvidenceCreate,
    EvidenceUpdate,
    EvidenceRead,
    EvidenceSummary,
)
from app.services import evidence_service

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.post("", response_model=EvidenceRead, status_code=201)
async def create_evidence(
    payload: EvidenceCreate,
    session: AsyncSession = Depends(get_session),
) -> EvidenceRead:
    evidence = await evidence_service.create_evidence(session, payload)
    return EvidenceRead.model_validate(evidence)


@router.get("", response_model=PaginatedResponse[EvidenceSummary])
async def list_evidence(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
) -> PaginatedResponse[EvidenceSummary]:
    items, total = await evidence_service.list_evidence(
        session, page=page, per_page=per_page
    )
    return PaginatedResponse(
        items=[EvidenceSummary.model_validate(i) for i in items],
        total=total,
        page=page,
        per_page=per_page,
        total_pages=max(1, math.ceil(total / per_page)),
    )


@router.get("/{evidence_id}", response_model=EvidenceRead)
async def get_evidence(
    evidence_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> EvidenceRead:
    evidence = await evidence_service.get_evidence(session, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return EvidenceRead.model_validate(evidence)


@router.patch("/{evidence_id}", response_model=EvidenceRead)
async def update_evidence(
    evidence_id: uuid.UUID,
    payload: EvidenceUpdate,
    session: AsyncSession = Depends(get_session),
) -> EvidenceRead:
    evidence = await evidence_service.get_evidence(session, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    updated = await evidence_service.update_evidence(session, evidence, payload)
    return EvidenceRead.model_validate(updated)


@router.delete("/{evidence_id}", status_code=204)
async def delete_evidence(
    evidence_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> None:
    evidence = await evidence_service.get_evidence(session, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    await evidence_service.delete_evidence(session, evidence)
