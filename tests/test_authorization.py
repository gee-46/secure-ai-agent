import time

import pytest

from src.auth.auth_service import register_user
from src.crypto import hybrid, keys
from src.security.authorization import (
    require_file_owner, AuthorizationError,
    check_decrypt_rate_limit, record_decrypt_failure, record_decrypt_success, RateLimitError,
)
from src.storage import file_store, repository


def _unique(prefix="u"):
    return f"{prefix}_{int(time.time() * 1_000_000)}"


def _make_encrypted_file_for(owner_user_id: str):
    passphrase = "key-passphrase-123"
    kp = keys.generate_rsa_keypair(passphrase)
    pub_path, priv_path = file_store.save_key_material(_unique("key"), kp.public_pem, kp.private_pem_encrypted)
    key_id = repository.create_key_pair_record(owner_user_id, "test-key", str(pub_path), str(priv_path))

    public_key = keys.load_public_key(kp.public_pem)
    container_bytes = hybrid.encrypt_file(
        b"owner-only secret", public_key, key_id, "Confidential", "Confidential", "secret.txt"
    )
    file_id, path = file_store.save_container(container_bytes)
    repository.create_file_record(
        file_id, owner_user_id, "secret.txt", str(path), key_id,
        "Confidential", "Confidential", 0.9, len(container_bytes)
    )
    return file_id


def test_owner_can_access_own_file():
    owner = register_user(_unique("owner"), "StrongPass123!")
    file_id = _make_encrypted_file_for(owner.user_id)
    record = require_file_owner(owner.user_id, file_id)
    assert record["owner_user_id"] == owner.user_id


def test_other_user_cannot_access_file():
    owner = register_user(_unique("owner"), "StrongPass123!")
    other = register_user(_unique("other"), "StrongPass123!")
    file_id = _make_encrypted_file_for(owner.user_id)
    with pytest.raises(AuthorizationError):
        require_file_owner(other.user_id, file_id)


def test_nonexistent_file_rejected():
    owner = register_user(_unique("owner"), "StrongPass123!")
    with pytest.raises(AuthorizationError):
        require_file_owner(owner.user_id, "does-not-exist")


def test_decrypt_rate_limiting():
    owner = register_user(_unique("owner"), "StrongPass123!")
    check_decrypt_rate_limit(owner.user_id)  # no error initially
    for _ in range(3):  # MAX_FAILED_ATTEMPTS = 3 in test env
        record_decrypt_failure(owner.user_id)
    with pytest.raises(RateLimitError):
        check_decrypt_rate_limit(owner.user_id)
    time.sleep(6.5)
    check_decrypt_rate_limit(owner.user_id)  # unlocked after lockout window
    record_decrypt_success(owner.user_id)
