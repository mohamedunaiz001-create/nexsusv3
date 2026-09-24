"""Safe evidence intake. Uploaded artifacts are never executed or unpacked."""

import hashlib
from uuid import uuid4
from pathlib import Path
from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.core.evidence import TEXT_EXTENSIONS
from app.core.exceptions import AppException
from app.core.security import get_current_user_id_optional
from app.db.session import get_db
from app.models.file import File as EvidenceFile
from app.schemas.common import APIResponse

router = APIRouter()


@router.get("", response_model=APIResponse)
async def list_files():
    return APIResponse(
        data=[], message="Evidence is attached to an investigation at upload time"
    )


@router.post("/analyze", response_model=APIResponse[dict])
async def analyze_evidence(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user_id: str | None = Depends(get_current_user_id_optional),
):
    """Return inert metadata and a bounded text preview for model context.

    Binary samples are hashed only; no execution, archive extraction, or dynamic
    analysis occurs in the web application.
    """
    name = Path(file.filename or "evidence").name
    data = await file.read()
    if len(data) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise AppException(
            f"File exceeds {settings.MAX_UPLOAD_SIZE_MB} MB limit", status_code=413
        )
    suffix = Path(name).suffix.lower()
    preview = ""
    if suffix in TEXT_EXTENSIONS:
        preview = data.decode("utf-8", errors="replace")[:12000]
    upload_dir = Path(settings.UPLOAD_DIR).resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    storage_path = upload_dir / f"{uuid4().hex}_{name}"
    storage_path.write_bytes(data)
    record = EvidenceFile(
        filename=name,
        content_type=file.content_type,
        size_bytes=len(data),
        storage_path=str(storage_path),
        sha256=hashlib.sha256(data).hexdigest(),
        uploader_id=current_user_id,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return APIResponse(
        data={
            "id": str(record.id),
            "filename": name,
            "size_bytes": len(data),
            "sha256": record.sha256,
            "content_type": file.content_type,
            "text_preview": preview,
            "binary_only": suffix not in TEXT_EXTENSIONS,
        },
        message="Evidence safely stored; binary content was not executed",
    )
