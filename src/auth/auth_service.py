"""User registration, login, and account-lockout logic.

Passwords are hashed with Argon2id (via argon2-cffi) and never stored or
logged in plaintext. Failed login attempts are rate-limited per account.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

from src.storage.db import connection_scope
from src.utils.config import SETTINGS
from src.utils.validation import (
    ValidationError,
    new_internal_id,
    validate_password_strength,
    validate_username,
)

_hasher = PasswordHasher()  # Argon2id defaults from argon2-cffi


class AuthError(Exception):
    """Generic authentication failure. User-facing message only, no internals."""


@dataclass(frozen=True)
class User:
    user_id: str
    username: str


def register_user(username: str, password: str) -> User:
    username = validate_username(username)
    validate_password_strength(password)

    password_hash = _hasher.hash(password)
    user_id = new_internal_id()
    now = datetime.now(timezone.utc).isoformat()

    with connection_scope() as conn:
        existing = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            raise ValidationError("Username is already taken.")
        conn.execute(
            "INSERT INTO users (user_id, username, password_hash, created_at, failed_attempts) "
            "VALUES (?, ?, ?, ?, 0)",
            (user_id, username, password_hash, now),
        )
    return User(user_id=user_id, username=username)


def _is_locked(locked_until: str | None) -> bool:
    if not locked_until:
        return False
    return datetime.fromisoformat(locked_until) > datetime.now(timezone.utc)


def login_user(username: str, password: str) -> User:
    """Authenticate a user. Raises AuthError on any failure (fail closed)."""
    with connection_scope() as conn:
        row = conn.execute(
            "SELECT user_id, username, password_hash, failed_attempts, locked_until "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if row is None:
            # Perform a dummy hash check to reduce username-enumeration timing signal.
            try:
                _hasher.verify(_hasher.hash("decoy-password"), password)
            except VerifyMismatchError:
                pass
            raise AuthError("Invalid username or password.")

        if _is_locked(row["locked_until"]):
            raise AuthError("Account temporarily locked due to repeated failed attempts.")

        try:
            _hasher.verify(row["password_hash"], password)
        except (VerifyMismatchError, InvalidHash):
            new_failed = row["failed_attempts"] + 1
            locked_until = None
            if new_failed >= SETTINGS.max_failed_attempts:
                locked_until = (
                    datetime.now(timezone.utc) + timedelta(seconds=SETTINGS.lockout_seconds)
                ).isoformat()
                new_failed = 0
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
                (new_failed, locked_until, row["user_id"]),
            )
            conn.commit()  # persist the failure/lockout state even though we raise below
            raise AuthError("Invalid username or password.")

        # Successful login: reset failure counters, rehash if argon2 params changed.
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?",
            (row["user_id"],),
        )
        return User(user_id=row["user_id"], username=row["username"])
