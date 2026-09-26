"""Anomaly model — flags suspicious forensic anomalies on fragments."""

import enum
import uuid

from sqlalchemy import String, Float, Text, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AnomalyType(str, enum.Enum):
    TIMESTOMPING = "timestomping"
    ENTROPY_SPIKE = "entropy_spike"
    ENTROPY_DROP = "entropy_drop"
    ANTI_FORENSIC = "anti_forensic"
    HIDDEN_DATA = "hidden_data"
    SLACK_SPACE = "slack_space"
    OVERWRITE_PATTERN = "overwrite_pattern"
    SIGNATURE_MISMATCH = "signature_mismatch"


class AnomalySeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Anomaly(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "anomalies"

    fragment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("fragments.id", ondelete="CASCADE"), nullable=False
    )

    # Anomaly classification
    anomaly_type: Mapped[AnomalyType] = mapped_column(
        Enum(AnomalyType), nullable=False
    )
    severity: Mapped[AnomalySeverity] = mapped_column(
        Enum(AnomalySeverity), nullable=False, default=AnomalySeverity.MEDIUM
    )

    # Detection info
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    detector_name: Mapped[str] = mapped_column(
        String(128), nullable=False, default="rule_based"
    )

    # Evidence
    details_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    fragment = relationship("Fragment", back_populates="anomalies")

    def __repr__(self) -> str:
        return (
            f"<Anomaly {self.anomaly_type.value} "
            f"severity={self.severity.value} confidence={self.confidence:.2f}>"
        )
