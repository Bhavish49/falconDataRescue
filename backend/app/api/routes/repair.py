"""
API endpoints for Corrupted File & Folder Upload, Diagnostics, and Neural Repair.
"""

from __future__ import annotations

import io
import uuid
import zipfile
from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import Response
from pathlib import Path

from app.services.repair_service import (
    diagnose_corruption,
    repair_file_buffer,
    REPAIRED_STORE
)
from app.services.recovery_jobs import create_recovery_job, get_recovery_job, recover_uploaded_file
from app.config import get_settings

router = APIRouter(prefix="/repair", tags=["repair"])


@router.get("/test-fixtures/synthetic-car")
async def get_synthetic_car_fixture():
    """Return the generated, controlled-damage image used by the demo button.

    This is intentionally a test fixture, not a claim that arbitrary image
    corruption can be recovered. It lets users exercise the real upload,
    repair, validation, and download pipeline without owning a damaged file.
    """
    fixture_path = Path(__file__).resolve().parents[4] / "test_corrupted_samples" / "synthetic_car_damaged.jpg"
    if not fixture_path.is_file():
        raise HTTPException(status_code=404, detail="Synthetic test fixture is not available")
    return Response(
        content=fixture_path.read_bytes(),
        media_type="image/jpeg",
        headers={"Content-Disposition": 'attachment; filename="synthetic_car_damaged.jpg"'},
    )


@router.get("/test-fixtures/{fixture_name}")
async def get_image_test_fixture(fixture_name: str):
    """Serve one allow-listed image fixture for the in-app batch test button."""
    allowed = {
        "synthetic_car_damaged.jpg",
        "recoverable_missing_eoi.jpg",
        "recoverable_truncated_scan.jpg",
        "recoverable_prefix_only.jpg",
        "pixel_corrupted_valid_jpeg.jpg",
        "uniform_black_valid_jpeg.jpg",
        "invalid_jpeg_bytes.jpg",
    }
    if fixture_name not in allowed:
        raise HTTPException(status_code=404, detail="Unknown image test fixture")
    fixture_path = Path(__file__).resolve().parents[4] / "test_corrupted_samples" / fixture_name
    if not fixture_path.is_file():
        raise HTTPException(status_code=404, detail="Image test fixture is not available")
    return Response(
        content=fixture_path.read_bytes(),
        media_type="image/jpeg",
        headers={"Content-Disposition": f'attachment; filename="{fixture_name}"'},
    )


@router.post("/jobs", status_code=202)
async def create_recovery_job_endpoint(files: list[UploadFile] = File(...)):
    """Queue multi-format recovery and return immediately with a pollable job ID."""
    settings = get_settings()
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    payload = []
    for uploaded in files:
        filename = Path(uploaded.filename or "recovered_image.bin").name
        contents = await uploaded.read()
        if not contents:
            raise HTTPException(status_code=400, detail=f"Empty file cannot be recovered: {filename}")
        if len(contents) > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File {filename} exceeds maximum size of {settings.max_upload_size_mb}MB",
            )
        payload.append((filename, contents))
    job = create_recovery_job(payload)
    return {"job_id": job["job_id"], "status": job["status"], "progress": job["progress"]}


@router.get("/jobs/{job_id}")
async def get_recovery_job_endpoint(job_id: str):
    job = get_recovery_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Recovery job not found")
    return job


@router.post("/diagnose")
async def diagnose_files(files: list[UploadFile] = File(...)):
    """Analyze uploaded files or folders for corruption, missing headers, and damage."""
    settings = get_settings()
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    results = []

    for f in files:
        # Check file size before reading
        contents = await f.read()
        if len(contents) > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File {f.filename or 'unknown'} exceeds maximum size of {settings.max_upload_size_mb}MB"
            )

        # Sanitize filename for security
        safe_filename = Path(f.filename or "unknown.bin").name
        diag = diagnose_corruption(safe_filename, contents)
        # Store temporary preview
        preview_hex = contents[:64].hex() if contents else ""
        results.append({
            **diag,
            "preview_hex": preview_hex
        })

    return {
        "status": "success",
        "total_files": len(results),
        "items": results
    }


@router.post("/process")
async def process_and_repair(files: list[UploadFile] = File(...)):
    """Repair all uploaded corrupted files and prepare download bundles."""
    settings = get_settings()
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    repaired_items = []

    # If multiple files, create a bundle zip as well
    bundle_zip_buffer = io.BytesIO()

    with zipfile.ZipFile(bundle_zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            contents = await f.read()
            if len(contents) > max_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"File {f.filename or 'unknown'} exceeds maximum size of {settings.max_upload_size_mb}MB"
                )

            # Sanitize filename for security
            safe_filename = Path(f.filename or "repaired_file.bin").name
            filename = safe_filename or "repaired_file.bin"
            if not contents:
                raise HTTPException(status_code=400, detail=f"Empty file cannot be recovered: {filename}")

            repaired_bytes, report = recover_uploaded_file(filename, contents)

            # Store only outputs that the decoder can open or partially decode.
            item_id = str(uuid.uuid4()) if report["status"] != "FAILED_RECOVERY" else None
            if item_id is not None:
                REPAIRED_STORE[item_id] = (f"repaired_{filename}", repaired_bytes)
            report["download_available"] = item_id is not None

            # Add to ZIP with sanitized filename
            if item_id is not None:
                safe_zip_filename = f"repaired_{filename}"
                # Prevent path traversal in ZIP entries
                safe_zip_filename = Path(safe_zip_filename).name
                zf.writestr(safe_zip_filename, repaired_bytes)

            repaired_items.append({
                "id": item_id,
                "file_name": filename,
                "report": report
            })

    # Store bundle zip
    bundle_id = str(uuid.uuid4())
    REPAIRED_STORE[bundle_id] = ("recovered_files_bundle.zip", bundle_zip_buffer.getvalue())

    return {
        "status": "success",
        "bundle_id": bundle_id,
        "total_repaired": len(repaired_items),
        "items": repaired_items
    }


@router.get("/download/{item_id}")
async def download_repaired_file(item_id: str):
    """Download single repaired file or complete zip bundle."""
    if item_id not in REPAIRED_STORE:
        raise HTTPException(status_code=404, detail="Repaired artifact not found or expired")

    filename, data = REPAIRED_STORE[item_id]

    # Sanitize filename for Content-Disposition header to prevent injection
    safe_filename = Path(filename).name

    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'}
    )
