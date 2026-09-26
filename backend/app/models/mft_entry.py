"""MFTEntry model — represents a single MFT record (deleted or active)."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    String, Integer, BigInteger, Boolean, Text, Enum, ForeignKey, DateTime,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class MFTEntryStatus(str, enum.Enum):
    ACTIVE = "active"
    DELETED = "deleted"
    PARTIALLY_OVERWRITTEN = "partially_overwritten"
    FULLY_OVERWRITTEN = "fully_overwritten"


class MFTEntry(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "mft_entries"

    partition_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("partitions.id", ondelete="CASCADE"), nullable=False
    )

    # MFT record info
    mft_record_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sequence_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parent_record_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    status: Mapped[MFTEntryStatus] = mapped_column(
        Enum(MFTEntryStatus), nullable=False, default=MFTEntryStatus.DELETED
    )
    is_directory: Mapped[bool] = mapped_column(Boolean, default=False)

    # File info
    file_name: Mapped[str] = mapped_column(String(512), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    file_extension: Mapped[str | None] = mapped_column(String(32), nullable=True)
    file_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    allocated_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # NTFS timestamps (SI = $STANDARD_INFORMATION)
    si_created: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    si_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    si_accessed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    si_mft_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # FN = $FILE_NAME timestamps (for timestomping detection)
    fn_created: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fn_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Flags
    has_data_runs: Mapped[bool] = mapped_column(Boolean, default=False)
    is_resident: Mapped[bool] = mapped_column(Boolean, default=False)
    is_compressed: Mapped[bool] = mapped_column(Boolean, default=False)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)

    # Attributes
    attributes_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    partition = relationship("Partition", back_populates="mft_entries")
    fragments = relationship("Fragment", back_populates="mft_entry", cascade="all, delete-orphan")
    artifacts = relationship("Artifact", back_populates="mft_entry", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<MFTEntry #{self.mft_record_number} {self.file_name} [{self.status.value}]>"
