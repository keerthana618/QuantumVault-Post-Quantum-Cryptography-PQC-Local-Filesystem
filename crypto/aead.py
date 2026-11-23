
"""AES-256-GCM authenticated encryption.

Blob layout:
    nonce (12 bytes) | ciphertext | authentication tag (16 bytes)

Every encryption uses a fresh random nonce.
Never reuse a nonce with the same key.
"""

from __future__ import annotations

import os
import importlib

from crypto.errors import (
    DecryptionError,
    InvalidKeyError,
    InvalidNonceError,
)


# AES-256-GCM constants
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16


# Load AES-GCM backend
try:
    _aesgcm_class = importlib.import_module(
        "cryptography.hazmat.primitives.ciphers.aead"
    ).AESGCM

    _BACKEND = "cryptography"

except ImportError:
    try:
        _pycrypto_aes = importlib.import_module("Crypto.Cipher.AES")

        class _AESGCMFallback:
            """AES-GCM fallback using PyCryptodome."""

            def __init__(self, key: bytes):
                self.key = key

            def encrypt(
                self,
                nonce: bytes,
                plaintext: bytes,
                aad: bytes = b"",
            ) -> bytes:
                cipher = _pycrypto_aes.new(
                    self.key,
                    _pycrypto_aes.MODE_GCM,
                    nonce=nonce,
                    mac_len=TAG_BYTES,
                )

                if aad:
                    cipher.update(aad)

                ciphertext, tag = cipher.encrypt_and_digest(plaintext)

                return ciphertext + tag

            def decrypt(
                self,
                nonce: bytes,
                ciphertext_and_tag: bytes,
                aad: bytes = b"",
            ) -> bytes:
                if len(ciphertext_and_tag) < TAG_BYTES:
                    raise ValueError("Invalid authentication tag.")

                ciphertext = ciphertext_and_tag[:-TAG_BYTES]
                tag = ciphertext_and_tag[-TAG_BYTES:]

                cipher = _pycrypto_aes.new(
                    self.key,
                    _pycrypto_aes.MODE_GCM,
                    nonce=nonce,
                    mac_len=TAG_BYTES,
                )

                if aad:
                    cipher.update(aad)

                return cipher.decrypt_and_verify(ciphertext, tag)

        _aesgcm_class = _AESGCMFallback
        _BACKEND = "pycryptodome"

    except ImportError as exc:
        raise ImportError(
            "AES-GCM requires either 'cryptography' "
            "or 'pycryptodome'."
        ) from exc


class AESGCM:
    """Small AES-GCM compatibility wrapper."""

    def __init__(self, key: bytes):
        self._cipher = _aesgcm_class(key)

    def encrypt(
        self,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> bytes:
        return self._cipher.encrypt(nonce, plaintext, aad)

    def decrypt(
        self,
        nonce: bytes,
        ciphertext_and_tag: bytes,
        aad: bytes = b"",
    ) -> bytes:
        return self._cipher.decrypt(nonce, ciphertext_and_tag, aad)


def generate_key() -> bytes:
    """Generate a cryptographically secure 256-bit AES key."""
    return os.urandom(KEY_BYTES)


def _check_key(key) -> bytes:
    """Validate and normalize the AES key."""

    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise InvalidKeyError(
            f"Key must be bytes, got {type(key).__name__}."
        )

    key = bytes(key)

    if len(key) != KEY_BYTES:
        raise InvalidKeyError(
            f"Key must be exactly {KEY_BYTES} bytes, "
            f"got {len(key)}."
        )

    return key


def _as_bytes(label: str, value) -> bytes:
    """Validate byte-like input."""

    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"{label} must be bytes, got {type(value).__name__}."
        )

    return bytes(value)


def _encrypt_with_nonce(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> bytes:
    """Encrypt using a caller-provided nonce. Tests only."""

    key = _check_key(key)
    nonce = _as_bytes("nonce", nonce)
    plaintext = _as_bytes("plaintext", plaintext)
    aad = _as_bytes("aad", aad)

    if len(nonce) != NONCE_BYTES:
        raise InvalidNonceError(
            f"Nonce must be {NONCE_BYTES} bytes, got {len(nonce)}."
        )

    encrypted = AESGCM(key).encrypt(nonce, plaintext, aad)

    return nonce + encrypted


def encrypt(
    key: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> bytes:
    """Encrypt and authenticate plaintext."""

    key = _check_key(key)
    plaintext = _as_bytes("plaintext", plaintext)
    aad = _as_bytes("aad", aad)

    nonce = os.urandom(NONCE_BYTES)

    return _encrypt_with_nonce(key, nonce, plaintext, aad)


def decrypt(
    key: bytes,
    blob: bytes,
    aad: bytes = b"",
) -> bytes:
    """Authenticate and decrypt an encrypted blob."""

    key = _check_key(key)
    blob = _as_bytes("blob", blob)
    aad = _as_bytes("aad", aad)

    if len(blob) < NONCE_BYTES + TAG_BYTES:
        raise DecryptionError(
            "Data is too short to be a valid encrypted blob."
        )

    nonce = blob[:NONCE_BYTES]
    ciphertext_and_tag = blob[NONCE_BYTES:]

    try:
        return AESGCM(key).decrypt(
            nonce,
            ciphertext_and_tag,
            aad,
        )

    except Exception as exc:
        # Normalize authentication failures from both backends.
        if (
            _BACKEND == "cryptography"
            and exc.__class__.__name__ == "InvalidTag"
        ):
            raise DecryptionError(
                "Decryption failed: wrong key, wrong AAD, "
                "or modified data."
            ) from exc

        if (
            _BACKEND == "pycryptodome"
            and isinstance(exc, ValueError)
        ):
            raise DecryptionError(
                "Decryption failed: wrong key, wrong AAD, "
                "or modified data."
            ) from exc

        raise
