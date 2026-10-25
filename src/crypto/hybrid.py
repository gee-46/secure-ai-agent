"""Hybrid encryption engine: AES-256-GCM for data, RSA-OAEP(SHA-256) to wrap the DEK.

This is the conventional hybrid-encryption construction: a fresh symmetric
Data Encryption Key (DEK) encrypts the bulk data efficiently with AES-GCM,
and the DEK itself is wrapped with the recipient's RSA public key so that
only the holder of the matching RSA private key can recover it. See
docs/ARCHITECTURE.md for the full data flow and docs/THREAT_MODEL.md for
limitations (e.g. no forward secrecy if the RSA private key is compromised).
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.crypto.container import (
    ContainerHeader,
    build_aad,
    deserialize_container,
    serialize_container,
    AES_ALGORITHM,
    RSA_ALGORITHM,
)

DEK_SIZE_BYTES = 32  # 256-bit
NONCE_SIZE_BYTES = 12  # 96-bit, required for AES-GCM

_OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


class DecryptionError(Exception):
    """Generic, user-safe decryption failure. Never carries sensitive detail."""


def encrypt_file(
    plaintext: bytes,
    recipient_public_key,
    recipient_key_id: str,
    classification: str,
    policy_name: str,
    display_name: str,
) -> bytes:
    """Encrypt plaintext bytes into a serialized, versioned container."""
    dek = os.urandom(DEK_SIZE_BYTES)
    nonce = os.urandom(NONCE_SIZE_BYTES)

    header = ContainerHeader(
        format_version=1,
        aes_algorithm=AES_ALGORITHM,
        rsa_algorithm=RSA_ALGORITHM,
        recipient_key_id=recipient_key_id,
        classification=classification,
        policy_name=policy_name,
        display_name=display_name,
    )
    aad = build_aad(header)

    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    wrapped_dek = recipient_public_key.encrypt(dek, _OAEP_PADDING)

    try:
        return serialize_container(header, nonce, wrapped_dek, ciphertext)
    finally:
        del dek  # best-effort; Python cannot guarantee secure wipe of immutable bytes


def decrypt_file(container_bytes: bytes, recipient_private_key) -> tuple[bytes, ContainerHeader]:
    """Decrypt a container. Raises DecryptionError on ANY failure (fail closed).

    No partial plaintext is ever returned: AESGCM.decrypt only returns a value
    after the authentication tag has been verified.
    """
    from src.crypto.container import ContainerFormatError

    try:
        header, nonce, wrapped_dek, ciphertext = deserialize_container(container_bytes)
    except ContainerFormatError as exc:
        raise DecryptionError(f"Invalid or corrupted encrypted file: {exc}") from exc

    aad = build_aad(header)

    try:
        dek = recipient_private_key.decrypt(wrapped_dek, _OAEP_PADDING)
    except Exception as exc:  # cryptography raises generic ValueError on bad unwrap
        raise DecryptionError("Decryption failed: the key does not match this file.") from exc

    try:
        aesgcm = AESGCM(dek)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "Decryption failed: the file is corrupted, tampered with, or the key is wrong."
        ) from exc
    finally:
        del dek

    return plaintext, header
