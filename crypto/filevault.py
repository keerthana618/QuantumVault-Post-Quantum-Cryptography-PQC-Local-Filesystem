"""QuantumVault file encryption envelope.

Blob layout:
    version byte | ML-KEM ciphertext | nonce (12 bytes) | ciphertext | tag (16 bytes)

The ML-KEM shared secret is expanded with HKDF-SHA256 to an AES-256 key.
The version byte and ML-KEM ciphertext are authenticated as AES-GCM AAD.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Union

from .aead import (
    NONCE_BYTES,
    TAG_BYTES,
    _encrypt_with_nonce,
    decrypt as aes_decrypt,
)
from .errors import (
    CryptoError,
    DecryptionError,
    DecapsulationError,
    InvalidKeyError,
)
from .kdf import hkdf_sha256
from .kem import MLKEM


FORMAT_VERSION = 1
VERSION_BYTES = 1
FILE_KEY_INFO = b"quantumvault-file-key-v1"
_CT_BY_VARIANT = {
    "ML-KEM-512": 768,
    "ML-KEM-768": 1088,
    "ML-KEM-1024": 1568,
}
_VARIANT_BY_PK_LENGTH = {
    800: "ML-KEM-512",
    1184: "ML-KEM-768",
    1568: "ML-KEM-1024",
}
_VARIANT_BY_CT_LENGTH = {length: variant for variant, length in _CT_BY_VARIANT.items()}
_VARIANT_BY_SK_LENGTH = {
    1632: "ML-KEM-512",
    2400: "ML-KEM-768",
    3168: "ML-KEM-1024",
}


def _variant_for_public_key(public_key: bytes) -> str:
    return _VARIANT_BY_PK_LENGTH.get(len(public_key), "ML-KEM-768")


def _header_aad(version: int, kem_ciphertext: bytes) -> bytes:
    return bytes((version,)) + kem_ciphertext


def _derive_file_key(shared_secret: bytes, nonce: bytes) -> bytes:
    return hkdf_sha256(
        shared_secret,
        salt=nonce,
        info=FILE_KEY_INFO,
        length=32,
    )


def encrypt_file_bytes(public_key: bytes, plaintext: bytes, variant: str | None = None) -> bytes:
    """Encrypt bytes for an ML-KEM public key and return the final vault blob."""
    public_key = bytes(public_key)
    plaintext = bytes(plaintext)
    selected_variant = variant or _variant_for_public_key(public_key)

    kem = MLKEM(selected_variant)
    kem_ciphertext, shared_secret = kem.encapsulate(public_key)

    nonce = os.urandom(NONCE_BYTES)
    file_key = _derive_file_key(shared_secret, nonce)
    aad = _header_aad(FORMAT_VERSION, kem_ciphertext)
    encrypted = _encrypt_with_nonce(file_key, nonce, plaintext, aad)
    # _encrypt_with_nonce repeats the nonce as the AES-GCM blob prefix.
    nonce_from_aead = encrypted[:NONCE_BYTES]
    encrypted = encrypted[NONCE_BYTES:]
    return bytes((FORMAT_VERSION,)) + kem_ciphertext + nonce_from_aead + encrypted


def decrypt_file_bytes(secret_key: bytes, blob: bytes, variant: str | None = None) -> bytes:
    """Authenticate and decrypt a final vault blob."""
    secret_key = bytes(secret_key)
    blob = bytes(blob)

    if len(blob) < VERSION_BYTES + 768 + NONCE_BYTES + TAG_BYTES:
        raise DecryptionError("Encrypted file is too short to be a valid QuantumVault blob.")
    if blob[0] != FORMAT_VERSION:
        raise DecryptionError(f"Unsupported vault format version: {blob[0]}.")

    if variant is not None:
        if variant not in _CT_BY_VARIANT:
            raise DecryptionError(f"Unsupported ML-KEM variant: {variant}.")
        selected_variant = variant
        kem_ciphertext_length = _CT_BY_VARIANT[selected_variant]
    else:
        selected_variant = _VARIANT_BY_SK_LENGTH.get(len(secret_key))
        if selected_variant is None:
            raise DecryptionError("Encrypted file KEM variant cannot be inferred from the secret key.")
        kem_ciphertext_length = _CT_BY_VARIANT[selected_variant]

    start = VERSION_BYTES
    kem_ciphertext = blob[start:start + kem_ciphertext_length]
    nonce = blob[start + kem_ciphertext_length:start + kem_ciphertext_length + NONCE_BYTES]
    encrypted = blob[start + kem_ciphertext_length + NONCE_BYTES:]

    if len(kem_ciphertext) != kem_ciphertext_length:
        raise DecryptionError("Encrypted file is truncated.")

    try:
        shared_secret = MLKEM(selected_variant).decapsulate(secret_key, kem_ciphertext)
    except (InvalidKeyError, DecapsulationError, CryptoError) as exc:
        raise DecryptionError("Could not decapsulate the encrypted file key.") from exc

    file_key = _derive_file_key(shared_secret, nonce)
    aad = _header_aad(FORMAT_VERSION, kem_ciphertext)
    try:
        return aes_decrypt(file_key, nonce + encrypted, aad)
    except DecryptionError:
        raise
    except Exception as exc:
        raise DecryptionError("Encrypted file authentication failed.") from exc


def encrypt_file(
    source: Union[bytes, bytearray, memoryview, str, os.PathLike],
    recipient_or_plaintext: Union[bytes, bytearray, memoryview, str, os.PathLike],
    destination: str | os.PathLike | None = None,
    variant: str | None = None,
) -> bytes:
    """Encrypt bytes or a filesystem path.

    Byte form: ``encrypt_file(public_key, plaintext, variant=...)``.
    Path form: ``encrypt_file(input_path, public_key, output_path, variant=...)``.
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        public_key = bytes(source)
        if isinstance(recipient_or_plaintext, (str, os.PathLike)):
            plaintext = Path(recipient_or_plaintext).read_bytes()
        else:
            plaintext = bytes(recipient_or_plaintext)
        blob = encrypt_file_bytes(public_key, plaintext, variant)
        if destination is not None:
            Path(destination).write_bytes(blob)
            os.chmod(destination, 0o600)
        return blob

    input_path = Path(source)
    public_key = bytes(recipient_or_plaintext)
    blob = encrypt_file_bytes(public_key, input_path.read_bytes(), variant)

    output_path = Path(destination) if destination is not None else input_path.with_suffix(input_path.suffix + ".qv")
    output_path.write_bytes(blob)
    os.chmod(output_path, 0o600)
    return blob


def decrypt_file(
    source: Union[bytes, bytearray, memoryview, str, os.PathLike],
    secret_or_blob: Union[bytes, bytearray, memoryview, str, os.PathLike],
    destination: str | os.PathLike | None = None,
    variant: str | None = None,
) -> bytes:
    """Decrypt bytes or a filesystem path."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        blob = (
            Path(secret_or_blob).read_bytes()
            if isinstance(secret_or_blob, (str, os.PathLike))
            else bytes(secret_or_blob)
        )
        plaintext = decrypt_file_bytes(bytes(source), blob, variant)
        if destination is not None:
            Path(destination).write_bytes(plaintext)
            os.chmod(destination, 0o600)
        return plaintext

    input_path = Path(source)
    plaintext = decrypt_file_bytes(bytes(secret_or_blob), input_path.read_bytes(), variant)
    output_path = Path(destination) if destination is not None else input_path.with_suffix(".dec")
    output_path.write_bytes(plaintext)
    os.chmod(output_path, 0o600)
    return plaintext

