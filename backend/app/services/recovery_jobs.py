"""Asynchronous recovery jobs with deterministic validation and optional AI review."""

from __future__ import annotations

import asyncio
import io
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any

from app.services.hf_service import query_huggingface_llm
from app.services.repair_service import REPAIRED_STORE, repair_file_buffer
from app.services.image_recovery import detect_image_format, recover_image
from app.services.ai_assisted_recovery import analyze_image_recovery


JOBS: dict[str, dict[str, Any]] = {}


def recover_uploaded_file(filename: str, contents: bytes) -> tuple[bytes, dict[str, Any]]:
    """Route each upload to the correct deterministic recovery engine."""
    image_format = detect_image_format(filename, contents)
    if image_format is not None:
        return recover_image(filename, contents)

    repaired_bytes, generic_report = repair_file_buffer(filename, contents)
    integrity_status = generic_report.get("integrity_status", "PARTIAL_RESCUE")
    status_map = {
        "FULL_RECONSTRUCTION": "VALIDATED_REPAIR",
        "SUBSTANTIAL_SALVAGE": "PARTIAL_RECOVERY",
        "PARTIAL_RESCUE": "PARTIAL_RECOVERY",
    }
    unchanged = repaired_bytes == contents
    status = "ORIGINAL_VALID" if unchanged else status_map.get(integrity_status, "FAILED_RECOVERY")
    confidence = 100 if unchanged else int(round(float(generic_report.get("integrity_score", 0))))
    warnings = []
    if status == "ORIGINAL_VALID":
        warnings.append("Original byte stream validated; no repair or reconstruction was applied")
        generic_report["integrity_status"] = "ORIGINAL_VALID"
        generic_report["integrity_score"] = 100
        generic_report["realism_assessment"] = "Original file passed deterministic checks. No recovery was performed."
        generic_report["repair_actions"] = ["Validated original byte stream; no repair applied"]
        generic_report["preview_markdown"] = (
            f"# Original File Validation: {filename}\n\n"
            "The input passed deterministic checks. No recovery or reconstruction was performed.\n"
        )
    elif status != "VALIDATED_REPAIR":
        warnings.append(
            "Recovered fragments or structure were validated, but the original byte stream was not fully proven intact"
        )
    report = {
        **generic_report,
        "file_name": filename,
        "format": generic_report.get("extension", "bin"),
        "status": status,
        "confidence": confidence,
        "original_hashes": {},
        "operations": generic_report.get("repair_actions", []),
        "warnings": warnings,
        "original_decode": {"ok": False, "scope": "non-image forensic parser"},
        "repaired_decode": {"ok": status != "FAILED_RECOVERY", "scope": "format-specific recovery"},
        "pixel_data_reconstructed": False,
        "content_recovery_status": "original_validated" if status == "ORIGINAL_VALID" else "fragment_salvage",
        "confidence_scope": "format_structure_and_recovered_fragments",
        "validation_scope": "format-specific forensic recovery",
    }
    return repaired_bytes, report


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_output(filename: str, data: bytes) -> dict[str, Any]:
    """Perform conservative format checks; never claim validation from a score alone."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin"
    checks: dict[str, bool] = {}

    if ext == "pdf":
        checks = {"header": data.startswith(b"%PDF-"), "eof_marker": b"%%EOF" in data[-1024:]}
    elif ext in {"jpg", "jpeg"}:
        checks = {"soi": data.startswith(b"\xff\xd8\xff"), "eoi": data.endswith(b"\xff\xd9")}
    elif ext == "png":
        checks = {
            "signature": data.startswith(b"\x89PNG\r\n\x1a\n"),
            "iend": data.endswith(b"IEND\xaeB`\x82"),
        }
    elif ext in {"docx", "xlsx", "zip"}:
        checks = {"zip_signature": data.startswith(b"PK\x03\x04")}
    else:
        checks = {"non_empty": bool(data)}

    passed = sum(checks.values())
    validated = passed == len(checks) and bool(checks)
    if ext in {"jpg", "jpeg", "png"}:
        # Marker checks prove only that the container boundaries look right;
        # they do not prove that pixels or scanlines were recovered.
        return {
            "validated": False,
            "checks": checks,
            "status": "PARTIAL_RECOVERY" if validated else "UNVALIDATED_RECONSTRUCTION",
            "validation_scope": "signature_and_end_marker_only",
        }
    return {
        "validated": validated,
        "checks": checks,
        "status": "VALIDATED_RECOVERY" if validated else "UNVALIDATED_RECONSTRUCTION",
    }


async def _run_ai_review(report: dict[str, Any]) -> dict[str, Any]:
    """Review image recovery metadata; never ask a text model to invent pixels."""
    if report.get("format") not in {"jpeg", "png"}:
        return {"status": "skipped", "reason": "image_only_pipeline"}

    prompt = (
        "Review these forensic fragments as evidence. Do not invent missing content. "
        "Review this image recovery metadata conservatively. Do not claim pixels were restored. "
        "Return JSON-like guidance with recovery_risk and warnings.\n\n"
        f"Filename: {report.get('file_name')}\n"
        f"Format: {report.get('format')}\n"
        f"Status: {report.get('status')}\n"
        f"Operations: {report.get('operations')}\n"
        f"Warnings: {report.get('warnings')}\n"
        f"Decoded metadata: {report.get('repaired_decode')}"
    )
    result = await query_huggingface_llm(
        prompt,
        "You are a forensic recovery reviewer. Analyze evidence conservatively; never claim bytes were recovered unless validated.",
    )
    return {
        "status": result.get("status", "error"),
        "provider": result.get("provider"),
        "model": result.get("model"),
        "response": result.get("response") or result.get("error"),
    }


async def _process(job_id: str) -> None:
    job = JOBS[job_id]
    try:
        job.update({"status": "analyzing", "progress": 10, "updated_at": _now()})
        results = []
        total = max(1, len(job["files"]))

        for index, (filename, contents) in enumerate(job["files"]):
            job.update({"status": "recovering", "progress": 15 + int(index / total * 55), "current_file": filename, "updated_at": _now()})
            repaired_bytes, report = recover_uploaded_file(filename, contents)
            report["integrity_status"] = report["status"]
            report["integrity_score"] = report["confidence"]

            downloadable = report["status"] != "FAILED_RECOVERY"
            item_id = str(uuid.uuid4()) if downloadable else None
            if item_id is not None:
                output_name = filename if report["status"] == "ORIGINAL_VALID" else f"repaired_{filename}"
                REPAIRED_STORE[item_id] = (output_name, repaired_bytes)
            report["download_available"] = downloadable
            results.append({"id": item_id, "file_name": filename, "report": report})
            job["items"] = results

        job.update({"status": "validating", "progress": 85, "updated_at": _now()})
        for (_source_name, source), item in zip(job["files"], results):
            candidate = source
            if item["id"] is not None:
                candidate = REPAIRED_STORE[item["id"]][1]
            if item["report"].get("format") in {"jpeg", "jpg", "png"}:
                ai_review = await asyncio.to_thread(
                    analyze_image_recovery,
                    item["file_name"],
                    source,
                    candidate,
                    item["report"],
                )
                item["report"]["ai_review"] = ai_review
                item["report"]["realism_assessment"] = ai_review.get("assessment")
            else:
                item["report"]["ai_review"] = {
                    "status": "skipped",
                    "provider": "local-evidence-ai",
                    "role": "image-only visual review",
                    "reason": "non_image_file",
                    "assessment": "Format-specific forensic recovery completed; visual AI review does not apply.",
                }

        downloadable_items = [item for item in results if item["id"] is not None]
        bundle_id = None
        if downloadable_items:
            bundle_buffer = io.BytesIO()
            with zipfile.ZipFile(bundle_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                for item in downloadable_items:
                    filename, data = REPAIRED_STORE[item["id"]]
                    archive.writestr(filename, data)
            bundle_id = str(uuid.uuid4())
            REPAIRED_STORE[bundle_id] = ("forensic_results_bundle.zip", bundle_buffer.getvalue())
        job.update({"status": "completed", "progress": 100, "items": results, "bundle_id": bundle_id, "completed_at": _now(), "updated_at": _now()})
    except Exception as exc:
        job.update({"status": "failed", "progress": 100, "error": str(exc), "updated_at": _now()})


def create_recovery_job(files: list[tuple[str, bytes]]) -> dict[str, Any]:
    job_id = str(uuid.uuid4())
    JOBS[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "progress": 0,
        "current_file": None,
        "items": [],
        "error": None,
        "created_at": _now(),
        "updated_at": _now(),
    }
    asyncio.create_task(_process_job(job_id, files))
    return JOBS[job_id]


async def _process_job(job_id: str, files: list[tuple[str, bytes]]) -> None:
    JOBS[job_id]["files"] = files
    await _process(job_id)


def get_recovery_job(job_id: str) -> dict[str, Any] | None:
    job = JOBS.get(job_id)
    if job is None:
        return None
    return {key: value for key, value in job.items() if key != "files"}
