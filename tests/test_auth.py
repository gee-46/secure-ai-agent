import time

import pytest

from src.auth.auth_service import register_user, login_user, AuthError
from src.utils.validation import ValidationError


def _unique_username(prefix="user"):
    return f"{prefix}_{int(time.time() * 1_000_000)}"


def test_register_and_login_success():
    username = _unique_username()
    register_user(username, "StrongPass123!")
    user = login_user(username, "StrongPass123!")
    assert user.username == username


def test_duplicate_registration_rejected():
    username = _unique_username()
    register_user(username, "StrongPass123!")
    with pytest.raises(ValidationError):
        register_user(username, "AnotherPass456!")


def test_login_wrong_password_rejected():
    username = _unique_username()
    register_user(username, "StrongPass123!")
    with pytest.raises(AuthError):
        login_user(username, "WrongPassword999!")


def test_login_unknown_user_rejected():
    with pytest.raises(AuthError):
        login_user(_unique_username("ghost"), "WhateverPass123!")


def test_weak_password_rejected():
    with pytest.raises(ValidationError):
        register_user(_unique_username(), "short")


def test_account_lockout_after_repeated_failures():
    username = _unique_username()
    register_user(username, "StrongPass123!")
    for _ in range(3):  # MAX_FAILED_ATTEMPTS is 3 in the test environment
        with pytest.raises(AuthError):
            login_user(username, "WrongPassword999!")
    with pytest.raises(AuthError):
        login_user(username, "StrongPass123!")  # locked out even with correct password
    time.sleep(6.5)  # LOCKOUT_SECONDS is 6 in the test environment
    user = login_user(username, "StrongPass123!")
    assert user.username == username


def test_password_never_stored_in_plaintext():
    from src.storage.db import connection_scope

    username = _unique_username()
    register_user(username, "StrongPass123!")
    with connection_scope() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    assert "StrongPass123!" not in row["password_hash"]
    assert row["password_hash"].startswith("$argon2id$")
