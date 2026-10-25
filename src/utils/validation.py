"""Input validation and sanitization helpers (safety boundary for uploads)."""
from __future__ import annotations

import re
import uuid

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_DISPLAY_NAME_LEN = 150


class ValidationError(Exception):
    """Raised when user-supplied input fails a safety check."""


def sanitize_display_filename(raw_name: str) -> str:
    """Strip path components and unsafe characters; never used as a real path."""
    if not raw_name:
        return "unnamed_file"
    name = raw_name.replace("\\", "/").split("/")[-1]
    name = _SAFE_NAME_RE.sub("_", name).strip("._")
    if not name:
        name = "unnamed_file"
    return name[:_MAX_DISPLAY_NAME_LEN]


def new_internal_id() -> str:
    """Unique internal identifier; never derived from user input."""
    return uuid.uuid4().hex


def validate_upload_size(size_bytes: int, max_mb: int) -> None:
    max_bytes = max_mb * 1024 * 1024
    if size_bytes <= 0:
        raise ValidationError("Uploaded file is empty.")
    if size_bytes > max_bytes:
        raise ValidationError(f"File exceeds the {max_mb} MB upload limit.")


def validate_username(username: str) -> str:
    username = username.strip()
    if not (3 <= len(username) <= 32):
        raise ValidationError("Username must be between 3 and 32 characters.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        raise ValidationError("Username may only contain letters, digits, '.', '_' and '-'.")
    return username


def validate_password_strength(password: str) -> None:
    if len(password) < 10:
        raise ValidationError("Password must be at least 10 characters long.")
    categories = sum(
        bool(re.search(pattern, password))
        for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    if categories < 3:
        raise ValidationError(
            "Password must contain at least 3 of: lowercase, uppercase, digit, symbol."
        )
