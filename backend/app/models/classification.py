"""Classification model — ML-based file type classification for an artifact."""

import uuid

from sqlalchemy import String, Float, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Classification(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "classifications"

    artifact_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Classification result
    predicted_type: Mapped[str] = mapped_column(String(128), nullable=False)
    predicted_mime: Mapped[str | None] = mapped_column(String(256), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    rank: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Model info
    classifier_name: Mapped[str] = mapped_column(
        String(128), nullable=False, default="random_forest"
    )
    classifier_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Top-k probabilities
    probabilities_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    artifact = relationship("Artifact", back_populates="classifications")

    def __repr__(self) -> str:
        return (
            f"<Classification {self.predicted_type} "
            f"confidence={self.confidence:.3f} rank={self.rank}>"
        )
