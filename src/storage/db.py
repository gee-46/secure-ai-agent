"""SQLite connection management and schema initialization.

All queries elsewhere in the codebase use parameterized statements
(never string-formatted SQL) to avoid injection.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from src.utils.config import SETTINGS

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
);

CREATE TABLE IF NOT EXISTS key_pairs (
    key_id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(user_id),
    label TEXT NOT NULL,
    public_key_path TEXT NOT NULL,
    private_key_path TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    file_id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(user_id),
    display_name TEXT NOT NULL,
    container_path TEXT NOT NULL,
    recipient_key_id TEXT NOT NULL REFERENCES key_pairs(key_id),
    classification TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    confidence REAL NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decrypt_attempts (
    user_id TEXT PRIMARY KEY REFERENCES users(user_id),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    user_id TEXT,
    username TEXT,
    event_type TEXT NOT NULL,
    file_id TEXT,
    status TEXT NOT NULL,
    detail TEXT
);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(SETTINGS.db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def connection_scope() -> Iterator[sqlite3.Connection]:
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def initialize_database(db_path: Path | None = None) -> None:
    target = db_path or SETTINGS.db_path
    conn = sqlite3.connect(target)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
