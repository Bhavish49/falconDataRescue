"""ArtifactIntegrity model — validation results for a recovered artifact."""

import enum
import uuid

from sqlalchemy import String, Float, Boolean, Text, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class IntegrityStatus(str, enum.Enum):
    VALID = "valid"
    PARTIAL = "partial"
    CORRUPTED = "corrupted"
    UNKNOWN = "unknown"


class ArtifactIntegrity(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "artifact_integrity"

    artifact_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    # Validation results
    status: Mapped[IntegrityStatus] = mapped_column(
        Enum(IntegrityStatus), nullable=False, default=IntegrityStatus.UNKNOWN
    )
    overall_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Individual checks
    magic_bytes_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    header_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    footer_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    crc_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    structure_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # Expected vs actual
    expected_magic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actual_magic: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Detailed results
    validation_details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    artifact = relationship("Artifact", back_populates="integrity")

    def __repr__(self) -> str:
        return (
            f"<ArtifactIntegrity artifact={self.artifact_id} "
            f"status={self.status.value} score={self.overall_score:.2f}>"
        )
