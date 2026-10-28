"""Test configuration: redirect the app to an isolated, temporary data directory
BEFORE any `src` module is imported, so the real dev database/storage/model are
never touched by the test suite."""
import os
import shutil
import sys
import tempfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))

_TEST_DIR = Path(tempfile.mkdtemp(prefix="ppaa_test_"))
os.environ["APP_DB_PATH"] = str(_TEST_DIR / "test_app.db")
os.environ["STORAGE_DIR"] = str(_TEST_DIR / "storage")
os.environ["KEYS_DIR"] = str(_TEST_DIR / "storage" / "keys")
os.environ["MODEL_PATH"] = str(_PROJECT_ROOT / "models" / "sensitivity_classifier.joblib")
os.environ["MAX_FAILED_ATTEMPTS"] = "3"
os.environ["LOCKOUT_SECONDS"] = "6"

from src.storage.db import initialize_database  # noqa: E402

initialize_database()

import atexit  # noqa: E402
atexit.register(lambda: shutil.rmtree(_TEST_DIR, ignore_errors=True))
