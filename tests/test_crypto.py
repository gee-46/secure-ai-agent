import json
import os

import pytest

from src.crypto import hybrid, keys, container


PASSPHRASE = "unit-test-passphrase-123"


@pytest.fixture(scope="module")
def keypair():
    return keys.generate_rsa_keypair(PASSPHRASE)


@pytest.fixture(scope="module")
def loaded_keys(keypair):
    public_key = keys.load_public_key(keypair.public_pem)
    private_key = keys.load_private_key(keypair.private_pem_encrypted, PASSPHRASE)
    return public_key, private_key


def _encrypt(plaintext: bytes, public_key, classification="Confidential"):
    return hybrid.encrypt_file(
        plaintext, public_key, recipient_key_id="key-1",
        classification=classification, policy_name="Confidential", display_name="file.txt",
    )


def test_round_trip_text(loaded_keys):
    public_key, private_key = loaded_keys
    plaintext = b"Hello, this is a confidential memo."
    container_bytes = _encrypt(plaintext, public_key)
    recovered, header = hybrid.decrypt_file(container_bytes, private_key)
    assert recovered == plaintext
    assert header.classification == "Confidential"


def test_round_trip_binary(loaded_keys):
    public_key, private_key = loaded_keys
    plaintext = bytes(range(256)) * 50
    container_bytes = _encrypt(plaintext, public_key)
    recovered, _ = hybrid.decrypt_file(container_bytes, private_key)
    assert recovered == plaintext


def test_round_trip_empty_file(loaded_keys):
    public_key, private_key = loaded_keys
    plaintext = b""
    container_bytes = _encrypt(plaintext, public_key)
    recovered, _ = hybrid.decrypt_file(container_bytes, private_key)
    assert recovered == b""


def test_round_trip_large_file(loaded_keys):
    public_key, private_key = loaded_keys
    plaintext = os.urandom(5 * 1024 * 1024)  # 5 MB
    container_bytes = _encrypt(plaintext, public_key)
    recovered, _ = hybrid.decrypt_file(container_bytes, private_key)
    assert recovered == plaintext


def test_unique_nonce_and_dek_per_encryption(loaded_keys):
    public_key, _ = loaded_keys
    c1 = _encrypt(b"same plaintext", public_key)
    c2 = _encrypt(b"same plaintext", public_key)
    h1, n1, w1, ct1 = container.deserialize_container(c1)
    h2, n2, w2, ct2 = container.deserialize_container(c2)
    assert n1 != n2
    assert w1 != w2
    assert ct1 != ct2


def test_wrong_passphrase_rejected(keypair):
    with pytest.raises(keys.KeyError_):
        keys.load_private_key(keypair.private_pem_encrypted, "totally-wrong-passphrase")


def test_wrong_private_key_rejected(loaded_keys):
    public_key, _ = loaded_keys
    other_keypair = keys.generate_rsa_keypair("another-passphrase-456")
    other_private_key = keys.load_private_key(other_keypair.private_pem_encrypted, "another-passphrase-456")

    container_bytes = _encrypt(b"secret data", public_key)
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(container_bytes, other_private_key)


def test_tampered_ciphertext_detected(loaded_keys):
    public_key, private_key = loaded_keys
    container_bytes = _encrypt(b"important data", public_key)
    payload = json.loads(container_bytes.decode("utf-8"))
    # Flip a byte in the ciphertext's base64 to simulate tampering.
    ct = bytearray(payload["ciphertext_b64"], "ascii")
    ct[5] = ct[5] ^ 1 if ct[5] != ord("A") else ord("B")
    payload["ciphertext_b64"] = ct.decode("ascii")
    tampered = json.dumps(payload).encode("utf-8")
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(tampered, private_key)


def test_tampered_nonce_detected(loaded_keys):
    public_key, private_key = loaded_keys
    container_bytes = _encrypt(b"important data", public_key)
    payload = json.loads(container_bytes.decode("utf-8"))
    nonce = bytearray(container.deserialize_container(container_bytes)[1])
    nonce[0] ^= 0xFF
    import base64
    payload["nonce_b64"] = base64.b64encode(bytes(nonce)).decode("ascii")
    tampered = json.dumps(payload).encode("utf-8")
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(tampered, private_key)


def test_tampered_metadata_detected(loaded_keys):
    """Changing authenticated header metadata (classification) must break the AAD check."""
    public_key, private_key = loaded_keys
    container_bytes = _encrypt(b"important data", public_key)
    payload = json.loads(container_bytes.decode("utf-8"))
    payload["classification"] = "Public"  # tamper with authenticated metadata
    tampered = json.dumps(payload).encode("utf-8")
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(tampered, private_key)


def test_corrupted_wrapped_dek_detected(loaded_keys):
    public_key, private_key = loaded_keys
    container_bytes = _encrypt(b"important data", public_key)
    payload = json.loads(container_bytes.decode("utf-8"))
    import base64
    bad_dek = base64.b64encode(os.urandom(384)).decode("ascii")
    payload["wrapped_dek_b64"] = bad_dek
    tampered = json.dumps(payload).encode("utf-8")
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(tampered, private_key)


def test_truncated_container_rejected(loaded_keys):
    _, private_key = loaded_keys
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(b'{"format_version": 1, "incomplete": true}', private_key)


def test_malformed_container_rejected(loaded_keys):
    _, private_key = loaded_keys
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(b"not even json {{{", private_key)


def test_unsupported_format_version_rejected(loaded_keys):
    public_key, private_key = loaded_keys
    container_bytes = _encrypt(b"data", public_key)
    payload = json.loads(container_bytes.decode("utf-8"))
    payload["format_version"] = 99
    tampered = json.dumps(payload).encode("utf-8")
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(tampered, private_key)


def test_empty_container_rejected(loaded_keys):
    _, private_key = loaded_keys
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(b"", private_key)


def test_unsupported_aes_algorithm_rejected(loaded_keys):
    public_key, private_key = loaded_keys
    container_bytes = _encrypt(b"data", public_key)
    payload = json.loads(container_bytes.decode("utf-8"))
    payload["aes_algorithm"] = "AES-128-CBC"
    tampered = json.dumps(payload).encode("utf-8")
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(tampered, private_key)


def test_unsupported_rsa_algorithm_rejected(loaded_keys):
    public_key, private_key = loaded_keys
    container_bytes = _encrypt(b"data", public_key)
    payload = json.loads(container_bytes.decode("utf-8"))
    payload["rsa_algorithm"] = "RSA-PKCS1v15"
    tampered = json.dumps(payload).encode("utf-8")
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(tampered, private_key)


def test_invalid_wrapped_dek_length_rejected(loaded_keys):
    public_key, private_key = loaded_keys
    container_bytes = _encrypt(b"data", public_key)
    payload = json.loads(container_bytes.decode("utf-8"))
    import base64
    payload["wrapped_dek_b64"] = base64.b64encode(b"short-dek-32-bytes-instead-of-384").decode("ascii")
    tampered = json.dumps(payload).encode("utf-8")
    with pytest.raises(hybrid.DecryptionError):
        hybrid.decrypt_file(tampered, private_key)
