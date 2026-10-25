"""Versioned encrypted container format.

The container is serialized as JSON with Base64-encoded binary fields.
Header metadata (everything except the ciphertext) is authenticated as
AES-GCM Associated Authenticated Data (AAD), so tampering with the header
(e.g. swapping the recipient key id or classification) is detected at
decrypt time, not silently accepted.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, asdict

FORMAT_VERSION = 1
AES_ALGORITHM = "AES-256-GCM"
RSA_ALGORITHM = "RSA-OAEP-SHA256"
SUPPORTED_VERSIONS = (1,)


class ContainerFormatError(Exception):
    """Raised when a container is malformed, truncated, or an unsupported version."""


@dataclass(frozen=True)
class ContainerHeader:
    format_version: int
    aes_algorithm: str
    rsa_algorithm: str
    recipient_key_id: str
    classification: str
    policy_name: str
    display_name: str


def build_aad(header: ContainerHeader) -> bytes:
    """Canonical, deterministic byte serialization of the header for AES-GCM AAD."""
    canonical = json.dumps(asdict(header), sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


def serialize_container(
    header: ContainerHeader,
    nonce: bytes,
    wrapped_dek: bytes,
    ciphertext: bytes,
) -> bytes:
    payload = {
        **asdict(header),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "wrapped_dek_b64": base64.b64encode(wrapped_dek).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(payload).encode("utf-8")


def deserialize_container(raw: bytes) -> tuple[ContainerHeader, bytes, bytes, bytes]:
    if not raw:
        raise ContainerFormatError("Encrypted container is empty.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContainerFormatError("Encrypted container is not valid JSON.") from exc

    required_fields = {
        "format_version", "aes_algorithm", "rsa_algorithm", "recipient_key_id",
        "classification", "policy_name", "display_name",
        "nonce_b64", "wrapped_dek_b64", "ciphertext_b64",
    }
    missing = required_fields - payload.keys()
    if missing:
        raise ContainerFormatError(f"Encrypted container is missing fields: {sorted(missing)}")

    version = payload["format_version"]
    if version not in SUPPORTED_VERSIONS:
        raise ContainerFormatError(f"Unsupported container format version: {version}")

    if payload["aes_algorithm"] != AES_ALGORITHM:
        raise ContainerFormatError(f"Unsupported AES algorithm: {payload['aes_algorithm']}")
    if payload["rsa_algorithm"] != RSA_ALGORITHM:
        raise ContainerFormatError(f"Unsupported RSA algorithm: {payload['rsa_algorithm']}")

    header = ContainerHeader(
        format_version=version,
        aes_algorithm=payload["aes_algorithm"],
        rsa_algorithm=payload["rsa_algorithm"],
        recipient_key_id=payload["recipient_key_id"],
        classification=payload["classification"],
        policy_name=payload["policy_name"],
        display_name=payload["display_name"],
    )

    try:
        nonce = base64.b64decode(payload["nonce_b64"], validate=True)
        wrapped_dek = base64.b64decode(payload["wrapped_dek_b64"], validate=True)
        ciphertext = base64.b64decode(payload["ciphertext_b64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ContainerFormatError("Encrypted container contains invalid Base64 data.") from exc

    if len(nonce) != 12:
        raise ContainerFormatError("Encrypted container has an invalid nonce length.")
    if len(wrapped_dek) != 384:
        raise ContainerFormatError(
            f"Encrypted container wrapped DEK length invalid: expected 384 bytes, got {len(wrapped_dek)}."
        )
    if len(ciphertext) < 16:
        raise ContainerFormatError("Encrypted container ciphertext is truncated.")

    return header, nonce, wrapped_dek, ciphertext
