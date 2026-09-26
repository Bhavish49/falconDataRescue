"""FragmentFeature model — ML feature vector extracted from a fragment."""

import uuid

from sqlalchemy import Float, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class FragmentFeature(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "fragment_features"

    fragment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("fragments.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    # Entropy features
    shannon_entropy: Mapped[float | None] = mapped_column(Float, nullable=True)
    chi_square: Mapped[float | None] = mapped_column(Float, nullable=True)
    monte_carlo_pi: Mapped[float | None] = mapped_column(Float, nullable=True)
    serial_correlation: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Byte frequency features (stored as JSONB — 256-element histogram)
    byte_frequency_histogram: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    byte_frequency_std: Mapped[float | None] = mapped_column(Float, nullable=True)
    byte_frequency_skew: Mapped[float | None] = mapped_column(Float, nullable=True)
    byte_frequency_kurtosis: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Structural features
    ascii_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    null_byte_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    printable_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    high_byte_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    longest_zero_run: Mapped[float | None] = mapped_column(Float, nullable=True)
    bigram_entropy: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Spatial features (relative to file)
    offset_distance_to_prev: Mapped[float | None] = mapped_column(Float, nullable=True)
    offset_distance_to_next: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_contiguous_with_prev: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Full feature vector for ML (flattened)
    feature_vector: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    fragment = relationship("Fragment", back_populates="features")

    def __repr__(self) -> str:
        return f"<FragmentFeature for fragment={self.fragment_id} entropy={self.shannon_entropy}>"
