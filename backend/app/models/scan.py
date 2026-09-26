"""Scan model — represents a single analysis run against an evidence item."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import String, Integer, Float, Text, Enum, ForeignKey, DateTime, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ScanType(str, enum.Enum):
    FULL = "full"
    MFT_ONLY = "mft_only"
    CARVING = "carving"
    QUICK = "quick"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scans"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False
    )
    scan_type: Mapped[ScanType] = mapped_column(
        Enum(ScanType), nullable=False, default=ScanType.FULL
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), nullable=False, default=ScanStatus.QUEUED
    )

    # Progress
    progress_pct: Mapped[float] = mapped_column(Float, default=0.0)
    total_entries_scanned: Mapped[int] = mapped_column(Integer, default=0)
    deleted_files_found: Mapped[int] = mapped_column(Integer, default=0)
    fragments_found: Mapped[int] = mapped_column(Integer, default=0)
    artifacts_recovered: Mapped[int] = mapped_column(Integer, default=0)

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Config & results
    config_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    evidence = relationship("Evidence", back_populates="scans")
    partitions = relationship("Partition", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    llm_interactions = relationship("LLMInteraction", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan {self.id} [{self.status.value}] {self.scan_type.value}>"
