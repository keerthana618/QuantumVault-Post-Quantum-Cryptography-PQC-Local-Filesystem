"""HKDF-SHA256 key derivation (RFC 5869).
 
Use this to turn a secret that is already strong (for example the shared secret
from ML-KEM) into one or more keys. Do NOT use it on passwords; passwords need a
slow function such as Argon2id.
"""
 
from __future__ import annotations
 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
 
from crypto.errors import KeyDerivationError
 
HASH_BYTES = 32                      # SHA-256 output size
MAX_LENGTH = 255 * HASH_BYTES        # RFC 5869 limit: 255 blocks of the hash size
 
 
def _require_bytes(label: str, value) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise KeyDerivationError(f"{label} must be bytes, got {type(value).__name__}.")
    return bytes(value)
 
 
def hkdf_sha256(
    ikm: bytes,
    *,
    info: bytes,
    length: int = 32,
    salt: bytes | None = None,
) -> bytes:
    """Derive `length` bytes from input key material `ikm`.
 
    ikm:    the secret to expand (must not be empty).
    info:   a label for the purpose, such as b"quantumvault-file-key-v1".
            Different labels give unrelated keys. It must not be empty.
    length: number of bytes wanted, from 1 to 8160. Default 32 (an AES-256 key).
    salt:   optional random value. None means "no salt", which RFC 5869 allows.
    """
    ikm = _require_bytes("ikm", ikm)
    info = _require_bytes("info", info)
    if salt is not None:
        salt = _require_bytes("salt", salt)
 
    if not ikm:
        raise KeyDerivationError("ikm must not be empty.")
    if not info:
        raise KeyDerivationError("info must not be empty; name the purpose of the key.")
    if isinstance(length, bool) or not isinstance(length, int):
        raise KeyDerivationError("length must be an integer.")
    if not 1 <= length <= MAX_LENGTH:
        raise KeyDerivationError(f"length must be between 1 and {MAX_LENGTH}, got {length}.")
 
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def hkdf(
    ikm: bytes,
    info: bytes,
    length: int = 32,
    salt: bytes | None = None,
) -> bytes:
    """Compatibility wrapper for positional HKDF callers."""
    return hkdf_sha256(ikm, info=info, length=length, salt=salt)
 