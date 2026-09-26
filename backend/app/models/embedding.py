"""Embedding model — stores vector embeddings for fragment similarity search."""

import uuid

from sqlalchemy import String, Integer, Float, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Embedding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "embeddings"

    fragment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("fragments.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    # Model info
    model_name: Mapped[str] = mapped_column(
        String(128), nullable=False, default="all-MiniLM-L6-v2"
    )
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dimension: Mapped[int] = mapped_column(Integer, nullable=False, default=384)

    # Vector stored as JSONB array (swap to pgvector for production-scale ANN)
    vector: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Pre-computed stats
    norm: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Relationships
    fragment = relationship("Fragment", back_populates="embedding")

    def __repr__(self) -> str:
        return f"<Embedding fragment={self.fragment_id} model={self.model_name} dim={self.dimension}>"
