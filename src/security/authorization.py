"""Authorization checks for decryption. Fails closed on any doubt.

Scope (MVP): only the owning user may decrypt a file. This is a
deliberate, documented scope limitation -- see docs/ARCHITECTURE.md and
docs/THREAT_MODEL.md. A filename or a self-reported user id is NEVER
treated as proof of ownership; ownership is always looked up server-side
from the `files` table using the authenticated session's user id, and the
classification embedded in a container is never trusted for access
decisions.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.storage.db import connection_scope
from src.utils.config import SETTINGS


class AuthorizationError(Exception):
    """Raised when a user is not authorized to decrypt a given file."""


class RateLimitError(Exception):
    """Raised when an account is temporarily locked out of decryption."""


def require_file_owner(user_id: str, file_id: str) -> dict:
    """Return the file record if `user_id` owns `file_id`; otherwise fail closed."""
    with connection_scope() as conn:
        row = conn.execute(
            "SELECT file_id, owner_user_id, display_name, container_path, recipient_key_id, "
            "classification, policy_name, confidence, size_bytes, created_at "
            "FROM files WHERE file_id = ?",
            (file_id,),
        ).fetchone()

    if row is None:
        raise AuthorizationError("File record not found.")
    if row["owner_user_id"] != user_id:
        raise AuthorizationError("You are not authorized to decrypt this file.")
    return dict(row)


def check_decrypt_rate_limit(user_id: str) -> None:
    with connection_scope() as conn:
        row = conn.execute(
            "SELECT locked_until FROM decrypt_attempts WHERE user_id = ?", (user_id,)
        ).fetchone()
    if row and row["locked_until"]:
        if datetime.fromisoformat(row["locked_until"]) > datetime.now(timezone.utc):
            raise RateLimitError("Too many failed decryption attempts. Try again later.")


def record_decrypt_failure(user_id: str) -> None:
    with connection_scope() as conn:
        row = conn.execute(
            "SELECT failed_attempts FROM decrypt_attempts WHERE user_id = ?", (user_id,)
        ).fetchone()
        failed = (row["failed_attempts"] if row else 0) + 1
        locked_until = None
        if failed >= SETTINGS.max_failed_attempts:
            locked_until = (
                datetime.now(timezone.utc) + timedelta(seconds=SETTINGS.lockout_seconds)
            ).isoformat()
            failed = 0
        conn.execute(
            "INSERT INTO decrypt_attempts (user_id, failed_attempts, locked_until) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET failed_attempts = ?, locked_until = ?",
            (user_id, failed, locked_until, failed, locked_until),
        )


def record_decrypt_success(user_id: str) -> None:
    with connection_scope() as conn:
        conn.execute(
            "INSERT INTO decrypt_attempts (user_id, failed_attempts, locked_until) "
            "VALUES (?, 0, NULL) "
            "ON CONFLICT(user_id) DO UPDATE SET failed_attempts = 0, locked_until = NULL",
            (user_id,),
        )
