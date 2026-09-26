"""Evidence service — business logic for evidence lifecycle management."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.evidence import Evidence, EvidenceStatus
from app.schemas.evidence import EvidenceCreate, EvidenceUpdate


async def create_evidence(session: AsyncSession, payload: EvidenceCreate) -> Evidence:
    """Register a new evidence item."""
    evidence = Evidence(
        name=payload.name,
        description=payload.description,
        evidence_type=payload.evidence_type,
        status=EvidenceStatus.REGISTERED,
        file_path=payload.file_path,
        file_size_bytes=payload.file_size_bytes,
        case_number=payload.case_number,
        examiner=payload.examiner,
        notes=payload.notes,
        metadata_json=payload.metadata_json,
    )
    session.add(evidence)
    await session.flush()
    return evidence


async def get_evidence(session: AsyncSession, evidence_id: uuid.UUID) -> Evidence | None:
    """Fetch a single evidence item by ID."""
    return await session.get(Evidence, evidence_id)


async def list_evidence(
    session: AsyncSession,
    *,
    page: int = 1,
    per_page: int = 20,
) -> tuple[list[Evidence], int]:
    """Return paginated evidence list with total count."""
    # Count
    count_q = select(func.count()).select_from(Evidence)
    total = (await session.execute(count_q)).scalar_one()

    # Items
    offset = (page - 1) * per_page
    items_q = (
        select(Evidence)
        .order_by(Evidence.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await session.execute(items_q)
    items = list(result.scalars().all())

    return items, total


async def update_evidence(
    session: AsyncSession,
    evidence: Evidence,
    payload: EvidenceUpdate,
) -> Evidence:
    """Patch mutable fields on an evidence item."""
    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(evidence, field, value)
    await session.flush()
    return evidence


async def delete_evidence(session: AsyncSession, evidence: Evidence) -> None:
    """Soft-delete is not implemented yet — hard deletes with CASCADE."""
    await session.delete(evidence)
    await session.flush()


def compute_file_hashes(file_path: str) -> dict[str, str]:
    """Compute MD5 and SHA-256 hashes for a file on disk (sync, for Celery tasks)."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)

    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
