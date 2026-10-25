"""Central configuration loaded from environment variables / .env file."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_PROJECT_ROOT / ".env")


def _resolve(path_str: str) -> Path:
    path = Path(path_str)
    if not path.is_absolute():
        path = _PROJECT_ROOT / path
    return path


@dataclass(frozen=True)
class Settings:
    project_root: Path
    db_path: Path
    storage_dir: Path
    keys_dir: Path
    model_path: Path
    max_upload_mb: int
    max_failed_attempts: int
    lockout_seconds: int


def load_settings() -> Settings:
    db_path = _resolve(os.getenv("APP_DB_PATH", "data/app.db"))
    storage_dir = _resolve(os.getenv("STORAGE_DIR", "storage"))
    keys_dir = _resolve(os.getenv("KEYS_DIR", "storage/keys"))
    model_path = _resolve(os.getenv("MODEL_PATH", "models/sensitivity_classifier.joblib"))

    db_path.parent.mkdir(parents=True, exist_ok=True)
    storage_dir.mkdir(parents=True, exist_ok=True)
    keys_dir.mkdir(parents=True, exist_ok=True)
    model_path.parent.mkdir(parents=True, exist_ok=True)

    return Settings(
        project_root=_PROJECT_ROOT,
        db_path=db_path,
        storage_dir=storage_dir,
        keys_dir=keys_dir,
        model_path=model_path,
        max_upload_mb=int(os.getenv("MAX_UPLOAD_MB", "25")),
        max_failed_attempts=int(os.getenv("MAX_FAILED_ATTEMPTS", "5")),
        lockout_seconds=int(os.getenv("LOCKOUT_SECONDS", "60")),
    )


SETTINGS = load_settings()
