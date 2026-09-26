"""Artifact model — a recovered file or reassembled data object."""

import enum
import uuid

from sqlalchemy import (
    String, Integer, BigInteger, Float, Text, Boolean, Enum, ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RecoveryMethod(str, enum.Enum):
    MFT_DIRECT = "mft_direct"
    FRAGMENT_REASSEMBLY = "fragment_reassembly"
    CARVING = "carving"
    AI_REASSEMBLY = "ai_reassembly"
    PARTIAL = "partial"


class ArtifactStatus(str, enum.Enum):
    RECOVERED = "recovered"
    PARTIAL = "partial"
    CORRUPTED = "corrupted"
    VERIFIED = "verified"
    EXPORTED = "exported"


class Artifact(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "artifacts"

    mft_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mft_entries.id", ondelete="SET NULL"), nullable=True
    )

    # File info
    original_name: Mapped[str] = mapped_column(String(512), nullable=False)
    original_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    file_extension: Mapped[str | None] = mapped_column(String(32), nullable=True)
    detected_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Size
    original_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    recovered_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Recovery info
    recovery_method: Mapped[RecoveryMethod] = mapped_column(
        Enum(RecoveryMethod), nullable=False, default=RecoveryMethod.MFT_DIRECT
    )
    status: Mapped[ArtifactStatus] = mapped_column(
        Enum(ArtifactStatus), nullable=False, default=ArtifactStatus.RECOVERED
    )
    recovery_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    fragment_count: Mapped[int] = mapped_column(Integer, default=1)

    # Hashes
    md5_hash: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sha256_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Priority
    priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    priority_explanation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Confidence
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_validated: Mapped[bool] = mapped_column(Boolean, default=False)

    metadata_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    mft_entry = relationship("MFTEntry", back_populates="artifacts")
    integrity = relationship(
        "ArtifactIntegrity", back_populates="artifact", uselist=False, cascade="all, delete-orphan"
    )
    classifications = relationship("Classification", back_populates="artifact", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Artifact {self.original_name} [{self.status.value}] confidence={self.confidence_score}>"
