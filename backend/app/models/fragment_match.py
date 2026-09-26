"""FragmentMatch model — predicted same-file probability between two fragments."""

import uuid

from sqlalchemy import Float, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class FragmentMatch(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "fragment_matches"

    fragment_a_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("fragments.id", ondelete="CASCADE"),
        nullable=False,
    )
    fragment_b_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("fragments.id", ondelete="CASCADE"),
        nullable=False,
    )

    # ML prediction
    match_probability: Mapped[float] = mapped_column(Float, nullable=False)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False, default="random_forest")
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Explainability
    feature_importances: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    explanation_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    fragment_a = relationship(
        "Fragment", foreign_keys=[fragment_a_id], back_populates="matches_as_source"
    )
    fragment_b = relationship(
        "Fragment", foreign_keys=[fragment_b_id], back_populates="matches_as_target"
    )

    def __repr__(self) -> str:
        return f"<FragmentMatch {self.fragment_a_id}↔{self.fragment_b_id} p={self.match_probability:.3f}>"
