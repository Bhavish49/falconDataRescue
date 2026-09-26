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

router = APIRouter(prefix="/forensics", tags=["forensics"])


@router.post("/carve-image")
async def carve_disk_image(file: UploadFile = File(...)):
    """Carve validated file-signature candidates from a forensic disk-image byte stream."""
    contents = await file.read()
    filename = file.filename or "disk_image.dd"

    res = parse_disk_image_and_recover(contents, filename)

    # Store individual items
    for item_id, (f_name, f_bytes) in res["raw_items_map"].items():
        CARVED_STORE[item_id] = (f_name, f_bytes)

    # Store bundle
    CARVED_STORE[res["bundle_id"]] = (f"carved_{filename}.zip", res["bundle_bytes"])

    return {
        "status": "success",
        "image_name": res["image_name"],
        "image_size": res["image_size"],
        "total_recovered": res["total_recovered"],
        "validated_candidates": res["validated_candidates"],
        "partial_candidates": res["partial_candidates"],
        "bundle_id": res["bundle_id"],
        "items": res["items"]
    }


@router.get("/download-carved/{item_id}")
async def download_carved_file(item_id: str):
    """Download single carved file or complete disk image recovery archive."""
    if item_id not in CARVED_STORE:
        raise HTTPException(status_code=404, detail="Carved artifact not found")
    
    filename, data = CARVED_STORE[item_id]
    
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
