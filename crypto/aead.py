"""AES-256-GCM authenticated encryption.
 
Blob layout produced by encrypt():  nonce (12 bytes) | ciphertext | tag (16 bytes)
 
Every call to encrypt() uses a fresh random nonce. Never reuse a nonce with the
same key, because that breaks GCM.
"""
 
from __future__ import annotations
 
import os
 
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
 
from crypto.errors import DecryptionError, InvalidKeyError, InvalidNonceError
 
KEY_BYTES = 32      # AES-256 only
NONCE_BYTES = 12    # the size GCM is designed for
TAG_BYTES = 16      # authentication tag appended by GCM
 
 
def generate_key() -> bytes:
    """Return a new random 32-byte key."""
    return os.urandom(KEY_BYTES)
 
 
def _check_key(key) -> bytes:
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise InvalidKeyError(f"key must be bytes, got {type(key).__name__}.")
    key = bytes(key)
    if len(key) != KEY_BYTES:
        raise InvalidKeyError(f"key must be exactly {KEY_BYTES} bytes, got {len(key)}.")
    return key
 
 
def _as_bytes(label: str, value) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{label} must be bytes, got {type(value).__name__}.")
    return bytes(value)
 
 
def _encrypt_with_nonce(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt with a caller-chosen nonce. For tests only; use encrypt() in real code."""
    key = _check_key(key)
    nonce = _as_bytes("nonce", nonce)
    if len(nonce) != NONCE_BYTES:
        raise InvalidNonceError(f"nonce must be {NONCE_BYTES} bytes, got {len(nonce)}.")
    plaintext = _as_bytes("plaintext", plaintext)
    aad = _as_bytes("aad", aad)
    # The library returns ciphertext + tag together.
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
 
 
def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt and authenticate plaintext. aad is extra data that is checked but not hidden."""
    return _encrypt_with_nonce(key, os.urandom(NONCE_BYTES), plaintext, aad)
 
 
def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Check and decrypt a blob made by encrypt(). Raises DecryptionError if anything was changed."""
    key = _check_key(key)
    blob = _as_bytes("blob", blob)
    aad = _as_bytes("aad", aad)
 
    if len(blob) < NONCE_BYTES + TAG_BYTES:
        raise DecryptionError("Data is too short to be a valid encrypted blob.")
 
    nonce = blob[:NONCE_BYTES]
    ciphertext_and_tag = blob[NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext_and_tag, aad)
    except InvalidTag as exc:
        # Wrong key, wrong aad, or modified data all look the same on purpose.
        raise DecryptionError("Decryption failed: wrong key, or the data was changed.") from exc
 