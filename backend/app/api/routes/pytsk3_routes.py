"""
API endpoints for pytsk3 & SleuthKit Disk Image Forensic Inode/Carving Recovery.
"""

from __future__ import annotations

import io
from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import Response

from app.services.pytsk3_recovery import (
    parse_disk_image_and_recover,
    CARVED_STORE
)
from app.services import ntfs_deleted_recovery as ndr

router = APIRouter(prefix="/forensics", tags=["forensics"])


@router.post("/carve-image")
async def carve_disk_image(file: UploadFile = File(...)):
    """Analyze an image and recover files using filesystem metadata when available."""
    contents = await file.read()
    filename = file.filename or "disk_image.dd"

    # Prefer authoritative NTFS deleted-record metadata over generic carving.
    # This prevents embedded PDFs from being presented as recovered files.
    if len(contents) >= 8 and contents[3:8] == b"NTFS ":
        res = ndr.scan_ntfs_image_bytes(contents, filename, max_items=200)
        result_store = ndr.DELETED_STORE
        analysis_mode = "ntfs_mft_deleted_file_recovery"
    else:
        res = parse_disk_image_and_recover(contents, filename)
        result_store = CARVED_STORE
        analysis_mode = "validated_signature_carving"

    # Store individual items
    for item_id, (f_name, f_bytes) in res["raw_items_map"].items():
        result_store[item_id] = (f_name, f_bytes)

    # Store bundle
    if "bundle_bytes" in res:
        result_store[res["bundle_id"]] = (f"carved_{filename}.zip", res["bundle_bytes"])

    return {
        "status": "success",
        "image_name": res["image_name"],
        "image_size": res["image_size"],
        "total_recovered": res["total_recovered"],
        "validated_candidates": res.get("validated_candidates", res.get("total_recovered", 0)),
        "partial_candidates": res.get("partial_candidates", 0),
        "bundle_id": res["bundle_id"],
        "analysis_mode": analysis_mode,
        "items": res["items"]
    }


@router.get("/download-carved/{item_id}")
async def download_carved_file(item_id: str):
    """Download single carved file or complete disk image recovery archive."""
    store = CARVED_STORE if item_id in CARVED_STORE else ndr.DELETED_STORE
    if item_id not in store:
        raise HTTPException(status_code=404, detail="Carved artifact not found")
    
    filename, data = store[item_id]
    
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
