"""LLMInteraction model — logs LLM calls for auditability and cost tracking."""

import enum
import uuid

from sqlalchemy import String, Integer, Float, Text, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class LLMProvider(str, enum.Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"


class LLMInteractionType(str, enum.Enum):
    ANALYSIS = "analysis"
    CLASSIFICATION = "classification"
    REASSEMBLY = "reassembly"
    PRIORITIZATION = "prioritization"
    REPORT_GENERATION = "report_generation"


class LLMInteraction(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "llm_interactions"

    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )

    # Provider info
    provider: Mapped[LLMProvider] = mapped_column(
        Enum(LLMProvider), nullable=False, default=LLMProvider.OPENAI
    )
    model_name: Mapped[str] = mapped_column(String(128), nullable=False, default="gpt-4o")
    interaction_type: Mapped[LLMInteractionType] = mapped_column(
        Enum(LLMInteractionType), nullable=False
    )

    # Request / Response
    prompt_text: Mapped[str] = mapped_column(Text, nullable=False)
    response_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    system_prompt: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Token usage
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Cost
    estimated_cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Latency (ms)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Structured result
    result_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="llm_interactions")

    def __repr__(self) -> str:
        return (
            f"<LLMInteraction {self.interaction_type.value} "
            f"model={self.model_name} tokens={self.total_tokens}>"
        )
