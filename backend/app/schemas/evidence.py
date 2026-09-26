"""Evidence Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.evidence import EvidenceType, EvidenceStatus


# ── Create ───────────────────────────────────────────────────────────────

class EvidenceCreate(BaseModel):
    name: str = Field(..., max_length=512, description="Human-readable evidence name")
    description: str | None = None
    evidence_type: EvidenceType = EvidenceType.DISK_IMAGE
    file_path: str = Field(..., max_length=2048)
    file_size_bytes: int | None = None
    case_number: str | None = Field(None, max_length=128)
    examiner: str | None = Field(None, max_length=256)
    notes: str | None = None
    metadata_json: dict | None = None


# ── Update ───────────────────────────────────────────────────────────────

class EvidenceUpdate(BaseModel):
    name: str | None = Field(None, max_length=512)
    description: str | None = None
    status: EvidenceStatus | None = None
    case_number: str | None = Field(None, max_length=128)
    examiner: str | None = Field(None, max_length=256)
    notes: str | None = None
    metadata_json: dict | None = None


# ── Read ─────────────────────────────────────────────────────────────────

class EvidenceRead(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    evidence_type: EvidenceType
    status: EvidenceStatus
    file_path: str
    file_size_bytes: int | None
    md5_hash: str | None
    sha256_hash: str | None
    case_number: str | None
    examiner: str | None
    notes: str | None
    metadata_json: dict | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Summary (for list views) ────────────────────────────────────────────

class EvidenceSummary(BaseModel):
    id: uuid.UUID
    name: str
    evidence_type: EvidenceType
    status: EvidenceStatus
    file_size_bytes: int | None
    case_number: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
