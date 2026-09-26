"""Fragment model — represents a contiguous data run belonging to a file."""

import enum
import uuid

from sqlalchemy import (
    String, Integer, BigInteger, Float, Boolean, Enum, ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class FragmentStatus(str, enum.Enum):
    INTACT = "intact"
    PARTIAL = "partial"
    OVERWRITTEN = "overwritten"
    CARVED = "carved"
    UNKNOWN = "unknown"


class Fragment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "fragments"

    mft_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mft_entries.id", ondelete="SET NULL"), nullable=True
    )

    # Data run info
    run_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    disk_offset_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    length_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    cluster_start: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cluster_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Status
    status: Mapped[FragmentStatus] = mapped_column(
        Enum(FragmentStatus), nullable=False, default=FragmentStatus.UNKNOWN
    )
    is_allocated: Mapped[bool] = mapped_column(Boolean, default=False)

    # Content analysis (quick stats)
    entropy: Mapped[float | None] = mapped_column(Float, nullable=True)
    md5_hash: Mapped[str | None] = mapped_column(String(32), nullable=True)
    detected_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    has_signature: Mapped[bool] = mapped_column(Boolean, default=False)

    metadata_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    mft_entry = relationship("MFTEntry", back_populates="fragments")
    features = relationship("FragmentFeature", back_populates="fragment", uselist=False, cascade="all, delete-orphan")
    matches_as_source = relationship(
        "FragmentMatch",
        foreign_keys="FragmentMatch.fragment_a_id",
        back_populates="fragment_a",
        cascade="all, delete-orphan",
    )
    matches_as_target = relationship(
        "FragmentMatch",
        foreign_keys="FragmentMatch.fragment_b_id",
        back_populates="fragment_b",
        cascade="all, delete-orphan",
    )
    anomalies = relationship("Anomaly", back_populates="fragment", cascade="all, delete-orphan")
    embedding = relationship("Embedding", back_populates="fragment", uselist=False, cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Fragment run={self.run_index} offset={self.disk_offset_bytes} len={self.length_bytes}>"
