"""Shared Pydantic schemas — pagination, health, error responses."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


# ── Health ───────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
    environment: str = "development"
    timestamp: datetime


# ── Pagination ───────────────────────────────────────────────────────────

class PaginationParams(BaseModel):
    page: int = Field(1, ge=1, description="Page number (1-indexed)")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.per_page


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    per_page: int
    total_pages: int


# ── Error ────────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    detail: str
    error_code: str | None = None


# ── Common fields ────────────────────────────────────────────────────────

class UUIDMixin(BaseModel):
    id: uuid.UUID


class TimestampMixin(BaseModel):
    created_at: datetime
    updated_at: datetime
