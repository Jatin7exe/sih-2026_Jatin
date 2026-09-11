from pathlib import PurePosixPath

ALLOWED_UPLOAD_TYPES: dict[str, str] = {
    # Documents & Text
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".doc": "application/msword",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".ppt": "application/vnd.ms-powerpoint",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xls": "application/vnd.ms-excel",
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
    ".txt": "text/plain",
    ".log": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".rtf": "application/rtf",
    
    # Web & Syndication
    ".xml": "application/xml",
    ".rss": "application/rss+xml",
    ".atom": "application/atom+xml",
    
    # Images & Visual
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".tiff": "image/tiff",
    ".tif": "image/tiff",
    ".bmp": "image/bmp",
    
    # Audio & Video
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".m4a": "audio/mp4",
    ".ogg": "audio/ogg",
    ".flac": "audio/flac",
    ".mp4": "video/mp4",
    ".mkv": "video/x-matroska",
    ".mov": "video/quicktime",
    ".avi": "video/x-msvideo",
    ".webm": "video/webm",
    
    # Cybersecurity & Structured Data
    ".stix": "application/json",
    ".taxii": "application/json",
    ".json": "application/json",
    ".jsonl": "application/jsonl",
    ".evtx": "application/xml",
    ".syslog": "text/plain",
    ".yara": "text/plain",
    ".sigma": "text/yaml",
    ".py": "text/x-python",
    ".sh": "application/x-sh",
    ".ps1": "application/powershell"
}

_KNOWN_TRANSPORT_TYPES = {"", "application/octet-stream"}


class UploadValidationError(ValueError):
    """Raised when an uploaded file is not an allowed document type."""


def normalize_filename(filename: str) -> str:
    """Strip any directory components from a client-supplied filename.

    Only the basename is kept (forward- and backslash separated) so the raw
    client value is never used for anything but display metadata.
    """
    cleaned = filename.replace("\\", "/")
    name = PurePosixPath(cleaned).name.strip()
    return name or "upload"


def validate_upload_type(filename: str, content_type: str | None) -> tuple[str, str]:
    """Validate a client upload against the allowed document types.

    The file extension is authoritative (the allowlist above); the MIME header
    is not trusted on its own. Returns ``(stored_content_type, extension)`` or
    raises :class:`UploadValidationError`.
    """
    name = normalize_filename(filename)
    ext = PurePosixPath(name).suffix.lower()
    canonical = ALLOWED_UPLOAD_TYPES.get(ext)
    if canonical is None:
        raise UploadValidationError(
            f"file type not supported (allowed: {', '.join(ALLOWED_UPLOAD_TYPES)})"
        )

    submitted = (content_type or "").split(";", 1)[0].strip().lower()
    if (
        submitted not in _KNOWN_TRANSPORT_TYPES
        and submitted in ALLOWED_UPLOAD_TYPES.values()
        and submitted != canonical
    ):
        raise UploadValidationError(
            f"content type {submitted!r} does not match file extension {ext!r}"
        )

    return canonical, ext