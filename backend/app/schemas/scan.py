"""Scan Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.scan import ScanType, ScanStatus


# ── Create ───────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    evidence_id: uuid.UUID
    scan_type: ScanType = ScanType.FULL
    config_json: dict | None = None


# ── Read ─────────────────────────────────────────────────────────────────

class ScanRead(BaseModel):
    id: uuid.UUID
    evidence_id: uuid.UUID
    scan_type: ScanType
    status: ScanStatus
    progress_pct: float
    total_entries_scanned: int
    deleted_files_found: int
    fragments_found: int
    artifacts_recovered: int
    started_at: datetime | None
    completed_at: datetime | None
    config_json: dict | None
    error_message: str | None
    summary_json: dict | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Progress ─────────────────────────────────────────────────────────────

class ScanProgress(BaseModel):
    id: uuid.UUID
    status: ScanStatus
    progress_pct: float
    total_entries_scanned: int
    deleted_files_found: int
    fragments_found: int
    artifacts_recovered: int

    model_config = {"from_attributes": True}


# ── Summary ──────────────────────────────────────────────────────────────

class ScanSummary(BaseModel):
    id: uuid.UUID
    evidence_id: uuid.UUID
    scan_type: ScanType
    status: ScanStatus
    progress_pct: float
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}
