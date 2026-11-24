import os

import pytest

from crypto.errors import DecryptionError
from crypto.filevault import (
    FORMAT_VERSION,
    decrypt_file,
    decrypt_file_bytes,
    encrypt_file,
    encrypt_file_bytes,
)
from crypto.kem import MLKEM


def test_encrypt_file_blob_layout_and_round_trip():
    kem = MLKEM("ML-KEM-768")
    public_key, secret_key = kem.generate_keypair()

    blob = encrypt_file_bytes(public_key, b"quantum vault file", "ML-KEM-768")

    assert blob[0] == FORMAT_VERSION
    assert len(blob) >= 1 + 1088 + 12 + 16
    assert decrypt_file_bytes(secret_key, blob, "ML-KEM-768") == b"quantum vault file"


def test_encrypt_file_uses_fresh_kem_ciphertext_and_nonce():
    kem = MLKEM("ML-KEM-768")
    public_key, _ = kem.generate_keypair()

    first = encrypt_file_bytes(public_key, b"same data")
    second = encrypt_file_bytes(public_key, b"same data")

    assert first != second


def test_tampered_file_fails():
    kem = MLKEM("ML-KEM-768")
    public_key, secret_key = kem.generate_keypair()
    blob = bytearray(encrypt_file_bytes(public_key, b"secret"))
    blob[-1] ^= 0x01

    with pytest.raises(DecryptionError):
        decrypt_file_bytes(secret_key, bytes(blob))


def test_wrong_recipient_fails():
    kem = MLKEM("ML-KEM-768")
    public_key, _ = kem.generate_keypair()
    _, wrong_secret_key = kem.generate_keypair()
    blob = encrypt_file_bytes(public_key, b"secret")

    with pytest.raises(DecryptionError):
        decrypt_file_bytes(wrong_secret_key, blob)


def test_encrypt_and_decrypt_file_paths(tmp_path):
    kem = MLKEM("ML-KEM-768")
    public_key, secret_key = kem.generate_keypair()
    source = tmp_path / "source.bin"
    encrypted = tmp_path / "source.bin.qv"
    decrypted = tmp_path / "source.bin.dec"
    source.write_bytes(b"filesystem round trip")

    encrypt_file(source, public_key, encrypted)
    assert encrypted.read_bytes()[0] == FORMAT_VERSION

    decrypt_file(encrypted, secret_key, decrypted)
    assert decrypted.read_bytes() == b"filesystem round trip"
    assert os.stat(encrypted).st_mode & 0o777 == 0o600
