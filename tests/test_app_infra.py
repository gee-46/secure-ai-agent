import time

from src.audit.audit_log import record_event, query_events, EVENT_LOGIN_SUCCESS, STATUS_SUCCESS
from src.auth.auth_service import register_user
from src.storage.db import get_connection
from src.utils.validation import (
    sanitize_display_filename, validate_upload_size, ValidationError, validate_username,
)


def test_database_tables_exist():
    conn = get_connection()
    try:
        tables = {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    finally:
        conn.close()
    assert {"users", "key_pairs", "files", "audit_log", "decrypt_attempts"} <= tables


def test_registration_creates_user_row():
    username = f"infra_{int(time.time() * 1_000_000)}"
    user = register_user(username, "StrongPass123!")
    assert user.user_id


def test_audit_event_recorded_and_queryable():
    username = f"audit_{int(time.time() * 1_000_000)}"
    record_event(EVENT_LOGIN_SUCCESS, STATUS_SUCCESS, username=username, detail="test login")
    events = query_events(username=username)
    assert len(events) == 1
    assert events[0].event_type == EVENT_LOGIN_SUCCESS


def test_audit_log_never_contains_password_field():
    """The audit_log module's INSERT statement must only ever receive the fixed
    set of safe columns; it must not read password/passphrase/private-key
    variables anywhere in its own code (only the module docstring may mention
    those words as a warning to callers)."""
    import ast
    import inspect
    from src.audit import audit_log

    tree = ast.parse(inspect.getsource(audit_log))
    # Drop the module docstring (an Expr whose value is a Constant string).
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        tree.body = tree.body[1:]
    code_without_docstring = ast.unparse(tree)

    for banned in ("password", "passphrase", "private_key", "dek"):
        assert banned not in code_without_docstring.lower()


def test_sanitize_filename_strips_path_traversal():
    assert sanitize_display_filename("../../etc/passwd") == "passwd"
    assert sanitize_display_filename("C:\\Windows\\System32\\evil.exe") == "evil.exe"


def test_upload_size_validation():
    validate_upload_size(1024, max_mb=1)
    try:
        validate_upload_size(2 * 1024 * 1024, max_mb=1)
        assert False, "expected ValidationError"
    except ValidationError:
        pass
    try:
        validate_upload_size(0, max_mb=1)
        assert False, "expected ValidationError"
    except ValidationError:
        pass


def test_username_validation_rejects_bad_characters():
    try:
        validate_username("bad name!")
        assert False, "expected ValidationError"
    except ValidationError:
        pass
    assert validate_username("  good_name.1  ") == "good_name.1"


def test_save_key_material_rejects_path_traversal():
    import pytest
    from src.storage.file_store import save_key_material

    with pytest.raises(ValueError, match="Invalid or unsafe storage identifier"):
        save_key_material("../../traversal_id", b"public", b"private")


def test_load_key_material_outside_keys_dir_rejected():
    import pytest
    from pathlib import Path
    from src.storage.file_store import load_key_material

    with pytest.raises(ValueError, match="Refusing to read a key path outside"):
        load_key_material(Path("../../secret.pub.pem"), Path("../../secret.enc.pem"))


def test_load_container_outside_storage_dir_rejected():
    import pytest
    from pathlib import Path
    from src.storage.file_store import load_container

    with pytest.raises(ValueError, match="Refusing to read a path outside"):
        load_container(Path("../../outside.enc"))


def test_audit_log_redacts_sensitive_detail():
    username = f"audit_sec_{int(time.time() * 1_000_000)}"
    record_event(
        EVENT_LOGIN_SUCCESS,
        STATUS_SUCCESS,
        username=username,
        detail="BEGIN CERTIFICATE or secret key token leakage",
    )
    events = query_events(username=username)
    assert len(events) == 1
    assert events[0].detail == "[REDACTED_SENSITIVE_DETAIL]"
