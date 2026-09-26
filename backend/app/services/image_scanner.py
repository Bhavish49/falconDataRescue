"""Bounded-memory image fragment scanner inspired by raw-block recovery tools."""

from __future__ import annotations

import binascii
import struct
from typing import Any, Iterator


DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024
JPEG_SOI = b"\xff\xd8\xff"
JPEG_EOI = b"\xff\xd9"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def iter_byte_offsets(data: bytes, needle: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[int]:
    """Find byte-pattern offsets with chunk overlap and bounded scan buffers."""
    if not needle:
        raise ValueError("needle must not be empty")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    overlap = len(needle) - 1
    tail = b""
    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + chunk_size]
        buffer = tail + chunk
        buffer_start = offset - len(tail)
        minimum = max(0, offset - overlap)
        search_at = 0
        while True:
            found = buffer.find(needle, search_at)
            if found < 0:
                break
            absolute = buffer_start + found
            if absolute >= minimum:
                yield absolute
            search_at = found + 1
        tail = buffer[-overlap:] if overlap else b""
        offset += len(chunk)


def scan_image_fragments(data: bytes, image_format: str) -> dict[str, Any]:
    """Return evidence-backed image candidate ranges and exact marker offsets."""
    if image_format == "jpeg":
        candidates = []
        for start in iter_byte_offsets(data, JPEG_SOI):
            end_marker = data.find(JPEG_EOI, start + len(JPEG_SOI))
            end = len(data) if end_marker < 0 else end_marker + len(JPEG_EOI)
            candidates.append({
                "offset": start,
                "end_offset": end,
                "length": end - start,
                "complete": end_marker >= 0,
                "marker": "SOI/EOI",
            })
        return {"format": "jpeg", "candidates": candidates, "scanned_bytes": len(data)}

    candidates = []
    for start in iter_byte_offsets(data, PNG_SIGNATURE):
        position = start + len(PNG_SIGNATURE)
        crc_errors = 0
        complete = False
        while position + 12 <= len(data):
            length = struct.unpack(">I", data[position : position + 4])[0]
            chunk_end = position + 12 + length
            if length > 64 * 1024 * 1024 or chunk_end > len(data):
                break
            chunk_type = data[position + 4 : position + 8]
            chunk_data = data[position + 8 : position + 8 + length]
            expected_crc = struct.unpack(">I", data[position + 8 + length : chunk_end])[0]
            actual_crc = binascii.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
            if actual_crc != expected_crc:
                crc_errors += 1
            position = chunk_end
            if chunk_type == b"IEND":
                complete = True
                break
        candidates.append({
            "offset": start,
            "end_offset": position,
            "length": position - start,
            "complete": complete,
            "crc_errors": crc_errors,
            "marker": "PNG signature/chunks/IEND",
        })
    return {"format": "png", "candidates": candidates, "scanned_bytes": len(data)}
