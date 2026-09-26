"""Partition model — represents an NTFS (or other) partition discovered during scan."""

import enum
import uuid

from sqlalchemy import String, Integer, BigInteger, Float, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class FilesystemType(str, enum.Enum):
    NTFS = "ntfs"
    FAT32 = "fat32"
    EXFAT = "exfat"
    EXT4 = "ext4"
    HFS_PLUS = "hfs_plus"
    APFS = "apfs"
    UNKNOWN = "unknown"


class Partition(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "partitions"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )

    # Partition geometry
    partition_index: Mapped[int] = mapped_column(Integer, nullable=False)
    start_offset: Mapped[int] = mapped_column(BigInteger, nullable=False)
    length_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    filesystem_type: Mapped[FilesystemType] = mapped_column(
        Enum(FilesystemType), nullable=False, default=FilesystemType.NTFS
    )

    # NTFS-specific
    cluster_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_clusters: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    mft_offset: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    volume_serial: Mapped[str | None] = mapped_column(String(64), nullable=True)
    volume_label: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Stats
    total_mft_entries: Mapped[int] = mapped_column(Integer, default=0)
    deleted_entries: Mapped[int] = mapped_column(Integer, default=0)
    recoverable_entries: Mapped[int] = mapped_column(Integer, default=0)

    metadata_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="partitions")
    mft_entries = relationship("MFTEntry", back_populates="partition", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Partition #{self.partition_index} {self.filesystem_type.value} @ {self.start_offset}>"
