"""Safe on-disk storage for encrypted file containers and RSA key material.

Files are stored under internally generated UUIDs, never under a
user-supplied path or filename, which prevents path traversal. Writes use
a write-to-temp-then-rename pattern for atomicity.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from src.utils.config import SETTINGS
from src.utils.validation import new_internal_id

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


def _validate_safe_id(identifier: str) -> None:
    if not isinstance(identifier, str) or not _SAFE_ID_RE.fullmatch(identifier):
        raise ValueError(f"Invalid or unsafe storage identifier: {identifier!r}")


def _atomic_write(target_path: Path, data: bytes) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.with_suffix(target_path.suffix + f".{os.getpid()}.tmp")
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, target_path)
    try:
        os.chmod(target_path, 0o600)
    except (NotImplementedError, OSError):
        pass  # best-effort on platforms without POSIX permission bits (e.g. some Windows setups)


def save_container(data: bytes) -> tuple[str, Path]:
    """Save an encrypted container under a fresh internal id. Returns (file_id, path)."""
    file_id = new_internal_id()
    path = SETTINGS.storage_dir / f"{file_id}.enc"
    _atomic_write(path, data)
    return file_id, path


def load_container(path: Path) -> bytes:
    resolved = path.resolve()
    storage_dir_res = SETTINGS.storage_dir.resolve()
    if storage_dir_res not in resolved.parents and resolved != storage_dir_res:
        raise ValueError("Refusing to read a path outside the managed storage directory.")
    if not resolved.is_file():
        raise FileNotFoundError(f"Container file not found: {resolved.name}")
    with open(resolved, "rb") as f:
        return f.read()


def save_key_material(key_id: str, public_pem: bytes, private_pem_encrypted: bytes) -> tuple[Path, Path]:
    _validate_safe_id(key_id)
    public_path = SETTINGS.keys_dir / f"{key_id}.pub.pem"
    private_path = SETTINGS.keys_dir / f"{key_id}.enc.pem"
    _atomic_write(public_path, public_pem)
    _atomic_write(private_path, private_pem_encrypted)
    return public_path, private_path


def load_key_material(public_path: Path, private_path: Path) -> tuple[bytes, bytes]:
    resolved_paths: list[Path] = []
    keys_dir_res = SETTINGS.keys_dir.resolve()
    for p in (public_path, private_path):
        resolved = p.resolve()
        if keys_dir_res not in resolved.parents and resolved != keys_dir_res:
            raise ValueError("Refusing to read a key path outside the managed keys directory.")
        if not resolved.is_file():
            raise FileNotFoundError(f"Key file not found: {resolved.name}")
        resolved_paths.append(resolved)
    return resolved_paths[0].read_bytes(), resolved_paths[1].read_bytes()
