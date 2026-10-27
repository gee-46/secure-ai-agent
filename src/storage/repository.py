"""Database-backed repository functions for key pairs and file records.
All queries are parameterized."""
from __future__ import annotations

from datetime import datetime, timezone

from src.storage.db import connection_scope
from src.utils.validation import new_internal_id


def create_key_pair_record(owner_user_id: str, label: str, public_path: str, private_path: str) -> str:
    key_id = new_internal_id()
    with connection_scope() as conn:
        conn.execute(
            "INSERT INTO key_pairs (key_id, owner_user_id, label, public_key_path, "
            "private_key_path, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (key_id, owner_user_id, label, public_path, private_path, datetime.now(timezone.utc).isoformat()),
        )
    return key_id


def list_key_pairs_for_user(owner_user_id: str) -> list[dict]:
    with connection_scope() as conn:
        rows = conn.execute(
            "SELECT key_id, label, public_key_path, private_key_path, created_at "
            "FROM key_pairs WHERE owner_user_id = ? ORDER BY created_at DESC",
            (owner_user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_key_pair(key_id: str) -> dict | None:
    with connection_scope() as conn:
        row = conn.execute(
            "SELECT key_id, owner_user_id, label, public_key_path, private_key_path, created_at "
            "FROM key_pairs WHERE key_id = ?",
            (key_id,),
        ).fetchone()
    return dict(row) if row else None


def create_file_record(
    file_id: str,
    owner_user_id: str,
    display_name: str,
    container_path: str,
    recipient_key_id: str,
    classification: str,
    policy_name: str,
    confidence: float,
    size_bytes: int,
) -> str:
    """`file_id` must be the same id under which the container was saved
    (see file_store.save_container), so the DB record and the stored file stay linked."""
    with connection_scope() as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_user_id, display_name, container_path, "
            "recipient_key_id, classification, policy_name, confidence, size_bytes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                file_id, owner_user_id, display_name, container_path, recipient_key_id,
                classification, policy_name, confidence, size_bytes,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    return file_id


def list_files_for_user(owner_user_id: str) -> list[dict]:
    with connection_scope() as conn:
        rows = conn.execute(
            "SELECT file_id, display_name, classification, policy_name, confidence, "
            "size_bytes, created_at FROM files WHERE owner_user_id = ? ORDER BY created_at DESC",
            (owner_user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def count_files_for_user(owner_user_id: str) -> int:
    with connection_scope() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM files WHERE owner_user_id = ?", (owner_user_id,)
        ).fetchone()
    return row["n"]


def classification_distribution(owner_user_id: str) -> dict[str, int]:
    with connection_scope() as conn:
        rows = conn.execute(
            "SELECT classification, COUNT(*) AS n FROM files WHERE owner_user_id = ? "
            "GROUP BY classification",
            (owner_user_id,),
        ).fetchall()
    return {r["classification"]: r["n"] for r in rows}
