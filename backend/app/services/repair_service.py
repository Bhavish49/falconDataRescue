"""
File & Folder Corruption Repair Service
Performs deep structural diagnostics, header reconstruction, magic-byte restoration,
entropy analysis, stream decompressions, fragment classification, and payload reassembly.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from app.services.forensic_recovery_engine import (
    calculate_entropy,
    calculate_entropy_map,
    classify_and_extract_entities,
    execute_full_forensic_recovery,
    extract_pdf_fragments,
    extract_docx_xlsx_fragments,
    extract_raw_text_code_fragments,
    build_fragment_relationship_graph,
)
from app.services.image_scanner import scan_image_fragments

# Known Magic Signatures
FILE_SIGNATURES = {
    "pdf": {"header": b"%PDF-", "footer": b"%%EOF", "name": "PDF Document"},
    "png": {"header": b"\x89PNG\r\n\x1a\n", "footer": b"IEND\xaeB`\x82", "name": "PNG Image"},
    "jpg": {"header": b"\xff\xd8\xff", "footer": b"\xff\xd9", "name": "JPEG Image"},
    "jpeg": {"header": b"\xff\xd8\xff", "footer": b"\xff\xd9", "name": "JPEG Image"},
    "zip": {"header": b"PK\x03\x04", "footer": b"PK\x05\x06", "name": "ZIP Archive"},
    "docx": {"header": b"PK\x03\x04", "footer": b"PK\x05\x06", "name": "Word Document (DOCX)"},
    "xlsx": {"header": b"PK\x03\x04", "footer": b"PK\x05\x06", "name": "Excel Spreadsheet (XLSX)"},
    "sqlite": {"header": b"SQLite format 3\x00", "footer": b"", "name": "SQLite 3 Database"},
    "mp4": {"header": b"\x00\x00\x00\x18ftypmp42", "footer": b"", "name": "MP4 Video"},
}


def detect_file_extension(filename: str) -> str:
    """Extract lowercase file extension."""
    parts = filename.rsplit(".", 1)
    return parts[1].lower() if len(parts) > 1 else "bin"


def diagnose_corruption(filename: str, data: bytes) -> dict:
    """Analyze file buffer for damage, missing headers, truncated endings, and entropy."""
    ext = detect_file_extension(filename)
    sig_info = FILE_SIGNATURES.get(ext)
    size = len(data)
    entropy = calculate_entropy(data)
    entropy_map = calculate_entropy_map(data)

    issues = []
    damage_score = 0
    is_header_damaged = False
    is_footer_damaged = False
    null_byte_count = data.count(b"\x00")
    null_byte_ratio = round(null_byte_count / max(1, size) * 100, 2)

    if size == 0:
        return {
            "file_name": filename,
            "size_bytes": 0,
            "status": "empty",
            "damage_score": 100,
            "detected_type": "Empty File",
            "issues": ["File has 0 bytes"],
            "entropy": 0.0,
            "entropy_sparkline": [0.0],
            "null_byte_ratio": 0.0,
            "repairable": False
        }

    if sig_info:
        expected_hdr = sig_info["header"]
        expected_ftr = sig_info["footer"]

        if expected_hdr and not data.startswith(expected_hdr):
            is_header_damaged = True
            damage_score += 40
            issues.append(f"Missing or corrupted {sig_info['name']} magic header")

        if expected_ftr and not data.endswith(expected_ftr):
            is_footer_damaged = True
            damage_score += 25
            issues.append("Truncated EOF footer marker (unexpected file termination)")
    else:
        if null_byte_ratio > 70:
            damage_score += 45
            issues.append("Excessive zero-padded blocks (>70% null bytes)")

    # Only set damage_score if actual issues are found
    # Don't mark healthy files as damaged by default
    if damage_score == 0 and size > 0 and len(issues) == 0:
        # File appears healthy, no damage detected
        pass

    # Apply minimum damage score of 5 only if issues were found but score is less than 5
    if damage_score > 0 and damage_score < 5:
        damage_score = 5
    # Cap maximum damage score at 100
    elif damage_score > 100:
        damage_score = 100
    # If no issues found, damage_score remains 0

    # Fast preliminary fragment peek
    if ext in {"jpg", "jpeg", "png"}:
        # Image payloads are binary. Never decode them as source/text because
        # arbitrary JPEG/PNG bytes produce convincing-looking garbage.
        frags = {"text_chunks": []}
    elif ext == "pdf" or b"%PDF-" in data or b"obj" in data:
        frags = extract_pdf_fragments(data)
    elif ext in ["docx", "xlsx", "zip"]:
        frags = extract_docx_xlsx_fragments(data)
    else:
        frags = extract_raw_text_code_fragments(data)

    classification = classify_and_extract_entities(filename, frags.get("text_chunks", []), data)
    text_chunks = frags.get("text_chunks", [])
    relationship_graph = build_fragment_relationship_graph(
        filename,
        text_chunks,
        classification["category"],
    )
    integrity_assessment = {
        "score": 100 - damage_score,
        "status": "healthy" if damage_score == 0 else "damaged",
        "recoverability": (
            "high" if damage_score <= 25 and text_chunks
            else "medium" if damage_score <= 60 or text_chunks
            else "low"
        ),
        "basis": "format markers, extracted fragments, and structural issue checks",
    }
    image_scan_format = "jpeg" if ext in {"jpg", "jpeg"} else "png" if ext == "png" else None
    image_scan = scan_image_fragments(data, image_scan_format) if image_scan_format else None

    return {
        "file_name": filename,
        "size_bytes": size,
        "extension": ext,
        "detected_type": sig_info["name"] if sig_info else "Binary Stream",
        "category": classification["category"],
        "priority": classification["priority"],
        "damage_score": damage_score,
        "health_score": 100 - damage_score,
        "is_header_damaged": is_header_damaged,
        "is_footer_damaged": is_footer_damaged,
        "entropy": entropy,
        "entropy_sparkline": entropy_map,
        "null_byte_ratio": null_byte_ratio,
        "fragments_detected": len(frags.get("text_chunks", [])),
        "fragment_samples": text_chunks[:50],
        "fragment_relationships": relationship_graph,
        "integrity_assessment": integrity_assessment,
        "image_candidates": image_scan.get("candidates", []) if image_scan else [],
        "issues": issues,
        "repairable": True
    }


def repair_file_buffer(filename: str, data: bytes) -> tuple[bytes, dict]:
    """Execute deep forensic AI recovery on corrupted bytes."""
    recovery_result = execute_full_forensic_recovery(filename, data)
    return recovery_result["repaired_bytes"], recovery_result["report"]


# In-memory storage for processed downloads
REPAIRED_STORE: dict[str, tuple[str, bytes]] = {}

