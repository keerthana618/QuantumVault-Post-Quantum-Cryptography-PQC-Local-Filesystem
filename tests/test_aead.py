import pytest

from crypto.aead import NONCE_BYTES, TAG_BYTES, decrypt, encrypt
from crypto.errors import DecryptionError

KEY = bytes(range(32))
AAD = b"header"
MSG = b"hello quantum vault"


def test_round_trip():
    assert decrypt(KEY, encrypt(KEY, MSG, AAD), AAD) == MSG


def test_round_trip_empty_aad():
    assert decrypt(KEY, encrypt(KEY, MSG, b""), b"") == MSG


def test_nonce_is_12_bytes():
    assert NONCE_BYTES == 12


def test_blob_layout():
    blob = encrypt(KEY, MSG, AAD)
    assert len(blob) == NONCE_BYTES + len(MSG) + TAG_BYTES


def test_nonce_is_random():
    assert encrypt(KEY, MSG, AAD) != encrypt(KEY, MSG, AAD)


def test_wrong_key_fails():
    blob = encrypt(KEY, MSG, AAD)
    with pytest.raises(DecryptionError):
        decrypt(bytes(32), blob, AAD)


def test_wrong_aad_fails():
    blob = encrypt(KEY, MSG, AAD)
    with pytest.raises(DecryptionError):
        decrypt(KEY, blob, b"other")


@pytest.mark.parametrize("pos", [0, NONCE_BYTES, -1])
def test_flipped_byte_fails(pos):
    blob = bytearray(encrypt(KEY, MSG, AAD))
    blob[pos] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt(KEY, bytes(blob), AAD)


def test_short_blob_fails():
    with pytest.raises(DecryptionError):
        decrypt(KEY, b"x" * (NONCE_BYTES + TAG_BYTES - 1), AAD)