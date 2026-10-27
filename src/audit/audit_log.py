"""Privacy-conscious audit logging.

Every event is written via parameterized SQL. Callers must never pass
plaintext content, passwords, passphrases, private keys, or DEKs into the
`detail` field — only short, safe status strings (see EVENT_TYPES).

Note: this is an ordinary application-level log table. It is NOT
cryptographically tamper-proof; a database administrator or anyone with
write access to the SQLite file can alter past rows. See
docs/THREAT_MODEL.md for the full discussion.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from src.storage.db import connection_scope
from src.utils.validation import new_internal_id

EVENT_ENCRYPT_SUCCESS = "ENCRYPT_SUCCESS"
EVENT_DECRYPT_SUCCESS = "DECRYPT_SUCCESS"
EVENT_LOGIN_FAILED = "LOGIN_FAILED"
EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_DECRYPT_DENIED = "DECRYPT_DENIED"
EVENT_INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
EVENT_CLASSIFICATION = "CLASSIFICATION"
EVENT_POLICY_DECISION = "POLICY_DECISION"
EVENT_KEY_GENERATED = "KEY_GENERATED"
EVENT_REGISTER = "REGISTER"

STATUS_SUCCESS = "SUCCESS"
STATUS_FAILURE = "FAILURE"
STATUS_DENIED = "DENIED"


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: str
    user_id: Optional[str]
    username: Optional[str]
    event_type: str
    file_id: Optional[str]
    status: str
    detail: Optional[str]


_SENSITIVE_INDICATORS = ("BEGIN", "TOKEN", "BEARER", "SECRET", "AUTH_HEADER")


def _sanitize_audit_detail(detail: Optional[str]) -> Optional[str]:
    if not detail:
        return detail
    for pattern in _SENSITIVE_INDICATORS:
        if pattern.lower() in detail.lower():
            return "[REDACTED_SENSITIVE_DETAIL]"
    return detail[:500]


def record_event(
    event_type: str,
    status: str,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    file_id: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    safe_detail = _sanitize_audit_detail(detail)
    try:
        with connection_scope() as conn:
            conn.execute(
                "INSERT INTO audit_log "
                "(event_id, timestamp, user_id, username, event_type, file_id, status, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    new_internal_id(),
                    datetime.now(timezone.utc).isoformat(),
                    user_id,
                    username,
                    event_type,
                    file_id,
                    status,
                    safe_detail,
                ),
            )
    except Exception:
        pass  # Fail closed safely: audit logging error must not leak or crash the application


def query_events(
    username: Optional[str] = None,
    event_type: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 500,
) -> list[AuditEvent]:
    clauses: list[str] = []
    params: list[object] = []

    if username:
        clauses.append("username = ?")
        params.append(username)
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if start_date:
        clauses.append("timestamp >= ?")
        params.append(start_date)
    if end_date:
        clauses.append("timestamp <= ?")
        params.append(end_date)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query = (
        f"SELECT event_id, timestamp, user_id, username, event_type, file_id, status, detail "
        f"FROM audit_log {where} ORDER BY timestamp DESC LIMIT ?"
    )
    params.append(limit)

    with connection_scope() as conn:
        rows = conn.execute(query, params).fetchall()

    return [
        AuditEvent(
            event_id=r["event_id"],
            timestamp=r["timestamp"],
            user_id=r["user_id"],
            username=r["username"],
            event_type=r["event_type"],
            file_id=r["file_id"],
            status=r["status"],
            detail=r["detail"],
        )
        for r in rows
    ]
