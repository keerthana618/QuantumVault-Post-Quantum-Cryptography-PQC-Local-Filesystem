import pytest

from crypto.key_utils import (
    generate_aes_key,
    validate_aes_key,
    generate_key_fingerprint,
    compare_key_fingerprints
)

from crypto.errors import InvalidKeyError


def test_generate_aes_key():
    key = generate_aes_key()

    assert isinstance(key, bytes)
    assert len(key) == 32


def test_validate_aes_key():
    key = generate_aes_key()

    assert validate_aes_key(key) is True


def test_invalid_key():
    with pytest.raises(InvalidKeyError):
        validate_aes_key(b"short")


def test_key_fingerprint():
    key = generate_aes_key()

    fingerprint = generate_key_fingerprint(key)

    assert len(fingerprint) == 64


def test_compare_same_keys():
    key = generate_aes_key()

    assert compare_key_fingerprints(key, key) is True


def test_compare_different_keys():
    key1 = generate_aes_key()
    key2 = generate_aes_key()

    assert compare_key_fingerprints(key1, key2) is False
