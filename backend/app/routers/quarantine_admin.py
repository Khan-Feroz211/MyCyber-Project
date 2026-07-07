from __future__ import annotations

import os
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..services.quarantine import QUARANTINE_DIR, quarantine_bytes
from ..dependencies import get_current_user
from ..db.models import User
from ..db.database import get_db
from ..mlops.logger import get_logger

router = APIRouter(prefix="/admin/quarantine", tags=["admin"])
logger = get_logger(__name__)


def _safe_path(name: str) -> Path:
    p = Path(name)
    # prevent directory traversal
    if p.name != name:
        raise ValueError("Invalid filename")
    return QUARANTINE_DIR / name


def _require_admin(user: User):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")


@router.get("/list")
async def list_quarantine(current_user: User = Depends(get_current_user)):
    _require_admin(current_user)
    items = []
    for f in QUARANTINE_DIR.iterdir():
        if f.is_file() and not f.suffix == ".json":
            meta_path = f.with_suffix(f.suffix + ".json")
            meta = {}
            if meta_path.exists():
                try:
                    import json

                    with open(meta_path, "r", encoding="utf-8") as mh:
                        meta = json.load(mh)
                except Exception:
                    meta = {}
            items.append({
                "name": f.name,
                "size": f.stat().st_size,
                "meta": meta,
            })
    return JSONResponse({"items": items})


@router.get("/item/{name}")
async def get_quarantine_item(name: str, current_user: User = Depends(get_current_user)):
    _require_admin(current_user)
    p = _safe_path(name)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Item not found")
    meta = {}
    meta_path = p.with_suffix(p.suffix + ".json")
    if meta_path.exists():
        import json

        with open(meta_path, "r", encoding="utf-8") as mh:
            meta = json.load(mh)
    return {"name": p.name, "size": p.stat().st_size, "meta": meta}


@router.get("/download/{name}")
async def download_quarantine_item(name: str, current_user: User = Depends(get_current_user)):
    _require_admin(current_user)
    p = _safe_path(name)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Item not found")
    return FileResponse(path=str(p), filename=p.name)


@router.post("/release/{name}")
async def release_quarantine_item(name: str, current_user: User = Depends(get_current_user)):
    _require_admin(current_user)
    p = _safe_path(name)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Item not found")
    released_dir = QUARANTINE_DIR.parent / "released"
    released_dir.mkdir(exist_ok=True)
    dest = released_dir / p.name
    p.rename(dest)
    # also move metadata
    meta = p.with_suffix(p.suffix + ".json")
    if meta.exists():
        meta.rename(dest.with_suffix(dest.suffix + ".json"))
    logger.info("Quarantine item released: %s by user %s", name, current_user.email)
    return {"released_to": str(dest)}


@router.delete("/{name}")
async def delete_quarantine_item(name: str, current_user: User = Depends(get_current_user)):
    _require_admin(current_user)
    p = _safe_path(name)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Item not found")
    # delete file and metadata
    meta = p.with_suffix(p.suffix + ".json")
    try:
        p.unlink()
        if meta.exists():
            meta.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    logger.info("Quarantine item deleted: %s by user %s", name, current_user.email)
    return {"deleted": name}
