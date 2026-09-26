"""Artifact Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.artifact import RecoveryMethod, ArtifactStatus


class ArtifactRead(BaseModel):
    id: uuid.UUID
    mft_entry_id: uuid.UUID | None
    original_name: str
    original_path: str | None
    file_extension: str | None
    detected_type: str | None
    mime_type: str | None
    original_size_bytes: int | None
    recovered_size_bytes: int | None
    recovery_method: RecoveryMethod
    status: ArtifactStatus
    recovery_path: str | None
    fragment_count: int
    md5_hash: str | None
    sha256_hash: str | None
    priority_score: float | None
    confidence_score: float | None
    is_validated: bool
    metadata_json: dict | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ArtifactSummary(BaseModel):
    id: uuid.UUID
    original_name: str
    file_extension: str | None
    detected_type: str | None
    recovered_size_bytes: int | None
    recovery_method: RecoveryMethod
    status: ArtifactStatus
    confidence_score: float | None
    priority_score: float | None
    created_at: datetime

    model_config = {"from_attributes": True}
