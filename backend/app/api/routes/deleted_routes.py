"""API endpoints for deleted-file recovery straight from NTFS volumes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from app.services import ntfs_deleted_recovery as ndr

router = APIRouter(prefix="/deleted", tags=["deleted"])


class ScanDriveRequest(BaseModel):
    drive: str
    max_items: int = 200


@router.get("/drives")
async def list_drives():
    return {"status": "success", "drives": ndr.list_drives()}


@router.post("/scan-drive")
async def scan_drive(req: ScanDriveRequest):
    letter = req.drive.strip()[:1]
    if not letter.isalpha():
        raise HTTPException(status_code=400, detail="Invalid drive letter")
    try:
        return ndr.scan_drive_for_deleted(letter, max_items=min(req.max_items, 500))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Drive scan failed: {exc}")


@router.get("/download/{item_id}")
async def download_deleted(item_id: str):
    if item_id not in ndr.DELETED_STORE:
        raise HTTPException(status_code=404, detail="Recovered artifact not found")
    filename, data = ndr.DELETED_STORE[item_id]
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
