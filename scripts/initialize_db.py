"""Create the SQLite schema (idempotent). Run once before first use.

Usage: python scripts/initialize_db.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.storage.db import initialize_database
from src.utils.config import SETTINGS

if __name__ == "__main__":
    initialize_database()
    print(f"Database initialized at: {SETTINGS.db_path}")
