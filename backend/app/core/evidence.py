"""Inert evidence storage and prompt context construction."""

from pathlib import Path
from sqlalchemy import select
from app.core.exceptions import AppException
from app.models.file import File

TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".json",
    ".csv",
    ".md",
    ".yml",
    ".yaml",
    ".py",
    ".js",
    ".ts",
    ".c",
    ".cpp",
    ".h",
}


async def evidence_context(
    db, file_ids: list[str], current_user_id: str | None = None
) -> str:
    """Builds the SAFE EVIDENCE CONTEXT block for the given file ids.

    File security: every file_id the caller passes must either be
    unowned (uploaded anonymously, uploader_id IS NULL) or owned by
    `current_user_id`. A file belonging to a *different* user raises a
    403 rather than being silently included or silently dropped — a
    user should get a clear error, not another user's evidence quietly
    showing up (or quietly not) in their model prompt.
    """
    if not file_ids:
        return ""
    rows = list(
        (await db.execute(select(File).where(File.id.in_(file_ids)))).scalars().all()
    )

    found_ids = {str(row.id) for row in rows}
    missing = [fid for fid in file_ids if fid not in found_ids]
    if missing:
        raise AppException(f"File(s) not found: {', '.join(missing)}", status_code=404)

    for row in rows:
        owner = str(row.uploader_id) if row.uploader_id else None
        if owner is not None and owner != current_user_id:
            raise AppException(
                f"File {row.id} does not belong to the current user",
                status_code=403,
            )

    parts = [
        "\n\nSAFE EVIDENCE CONTEXT (never execute artifacts; reason only from this data):"
    ]
    for row in rows:
        parts.append(
            f"\nFile: {row.filename}\nSHA-256: {row.sha256}\nSize: {row.size_bytes} bytes"
        )
        path = Path(row.storage_path)
        if path.suffix.lower() in TEXT_EXTENSIONS and path.is_file():
            parts.append(
                "Text preview:\n"
                + path.read_text(encoding="utf-8", errors="replace")[:12000]
            )
        else:
            parts.append(
                "Binary evidence retained as metadata/hash only; it was not executed or unpacked."
            )
    return "\n".join(parts)
