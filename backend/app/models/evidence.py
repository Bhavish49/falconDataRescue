"""Evidence model — represents a disk image or physical device under analysis."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import String, BigInteger, Text, Enum, DateTime, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class EvidenceType(str, enum.Enum):
    DISK_IMAGE = "disk_image"
    RAW_DD = "raw_dd"
    E01 = "e01"
    VMDK = "vmdk"
    VHD = "vhd"
    PHYSICAL = "physical"


class EvidenceStatus(str, enum.Enum):
    REGISTERED = "registered"
    MOUNTING = "mounting"
    MOUNTED = "mounted"
    SCANNING = "scanning"
    COMPLETED = "completed"
    ERROR = "error"


class Evidence(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "evidence"

    # Core fields
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_type: Mapped[EvidenceType] = mapped_column(
        Enum(EvidenceType), nullable=False, default=EvidenceType.DISK_IMAGE
    )
    status: Mapped[EvidenceStatus] = mapped_column(
        Enum(EvidenceStatus), nullable=False, default=EvidenceStatus.REGISTERED
    )

    # File info
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    file_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    md5_hash: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sha256_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Case metadata
    case_number: Mapped[str | None] = mapped_column(String(128), nullable=True)
    examiner: Mapped[str | None] = mapped_column(String(256), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    scans = relationship("Scan", back_populates="evidence", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Evidence {self.name} [{self.status.value}]>"
