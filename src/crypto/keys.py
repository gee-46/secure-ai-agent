"""RSA key-pair generation and passphrase-protected private key storage.

The private key is encrypted at rest using the `cryptography` library's
built-in PEM encryption (PBKDF2-HMAC-backed `BestAvailableEncryption`),
which derives a key-encryption key from the user's passphrase. The
passphrase itself is never stored or logged.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

RSA_KEY_SIZE = 3072
RSA_PUBLIC_EXPONENT = 65537


class KeyError_(Exception):
    """Raised for key-loading/decryption failures. Never includes key material."""


@dataclass(frozen=True)
class KeyPairFiles:
    public_pem: bytes
    private_pem_encrypted: bytes


def generate_rsa_keypair(passphrase: str) -> KeyPairFiles:
    """Generate an RSA-3072 key pair and encrypt the private key with the passphrase."""
    if len(passphrase) < 8:
        raise ValueError("Private key passphrase must be at least 8 characters.")

    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE
    )
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    return KeyPairFiles(public_pem=public_pem, private_pem_encrypted=private_pem)


def load_public_key(public_pem: bytes):
    return serialization.load_pem_public_key(public_pem)


def load_private_key(private_pem_encrypted: bytes, passphrase: str):
    """Decrypt and load the private key. Raises KeyError_ on a wrong passphrase."""
    try:
        return serialization.load_pem_private_key(
            private_pem_encrypted, password=passphrase.encode("utf-8")
        )
    except (ValueError, TypeError) as exc:
        raise KeyError_("Incorrect passphrase or corrupted private key.") from exc
