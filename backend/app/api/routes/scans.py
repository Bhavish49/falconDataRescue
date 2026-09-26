"""Scan management routes."""

from __future__ import annotations

import math
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.schemas.common import PaginatedResponse
from app.schemas.scan import ScanCreate, ScanRead, ScanProgress, ScanSummary
from app.services import evidence_service, scan_service

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=201)
async def create_scan(
    payload: ScanCreate,
    session: AsyncSession = Depends(get_session),
) -> ScanRead:
    # Validate evidence exists
    evidence = await evidence_service.get_evidence(session, payload.evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    scan = await scan_service.create_scan(session, payload)
    return ScanRead.model_validate(scan)


@router.get("", response_model=PaginatedResponse[ScanSummary])
async def list_scans(
    evidence_id: uuid.UUID | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
) -> PaginatedResponse[ScanSummary]:
    items, total = await scan_service.list_scans(
        session, evidence_id=evidence_id, page=page, per_page=per_page
    )
    return PaginatedResponse(
        items=[ScanSummary.model_validate(i) for i in items],
        total=total,
        page=page,
        per_page=per_page,
        total_pages=max(1, math.ceil(total / per_page)),
    )


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ScanRead:
    scan = await scan_service.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanRead.model_validate(scan)


@router.get("/{scan_id}/progress", response_model=ScanProgress)
async def get_scan_progress(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ScanProgress:
    scan = await scan_service.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanProgress.model_validate(scan)
