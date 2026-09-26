"""Scan service — business logic for scan orchestration and progress tracking."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanCreate


async def create_scan(session: AsyncSession, payload: ScanCreate) -> Scan:
    """Queue a new scan for an evidence item."""
    scan = Scan(
        evidence_id=payload.evidence_id,
        scan_type=payload.scan_type,
        status=ScanStatus.QUEUED,
        config_json=payload.config_json,
    )
    session.add(scan)
    await session.flush()
    return scan


async def get_scan(session: AsyncSession, scan_id: uuid.UUID) -> Scan | None:
    """Fetch a single scan by ID."""
    return await session.get(Scan, scan_id)


async def list_scans(
    session: AsyncSession,
    *,
    evidence_id: uuid.UUID | None = None,
    page: int = 1,
    per_page: int = 20,
) -> tuple[list[Scan], int]:
    """Return paginated scans, optionally filtered by evidence_id."""
    base = select(Scan)
    count_base = select(func.count()).select_from(Scan)

    if evidence_id is not None:
        base = base.where(Scan.evidence_id == evidence_id)
        count_base = count_base.where(Scan.evidence_id == evidence_id)

    total = (await session.execute(count_base)).scalar_one()

    offset = (page - 1) * per_page
    items_q = base.order_by(Scan.created_at.desc()).offset(offset).limit(per_page)
    result = await session.execute(items_q)
    items = list(result.scalars().all())

    return items, total


async def update_scan_status(
    session: AsyncSession,
    scan: Scan,
    status: ScanStatus,
    *,
    error_message: str | None = None,
) -> Scan:
    """Transition a scan to a new status."""
    scan.status = status

    if status == ScanStatus.RUNNING and scan.started_at is None:
        scan.started_at = datetime.now(timezone.utc)
    elif status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        scan.completed_at = datetime.now(timezone.utc)

    if error_message is not None:
        scan.error_message = error_message

    await session.flush()
    return scan


async def update_scan_progress(
    session: AsyncSession,
    scan: Scan,
    *,
    progress_pct: float | None = None,
    total_entries_scanned: int | None = None,
    deleted_files_found: int | None = None,
    fragments_found: int | None = None,
    artifacts_recovered: int | None = None,
) -> Scan:
    """Increment scan progress counters."""
    if progress_pct is not None:
        scan.progress_pct = progress_pct
    if total_entries_scanned is not None:
        scan.total_entries_scanned = total_entries_scanned
    if deleted_files_found is not None:
        scan.deleted_files_found = deleted_files_found
    if fragments_found is not None:
        scan.fragments_found = fragments_found
    if artifacts_recovered is not None:
        scan.artifacts_recovered = artifacts_recovered

    await session.flush()
    return scan
