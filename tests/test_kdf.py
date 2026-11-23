import pytest

from crypto import kdf

# >>> EDIT THIS ONE FUNCTION to call your real HKDF function in kdf.py <<<
def derive(ikm: bytes, info: bytes) -> bytes:
    return kdf.hkdf(ikm, info)  # e.g. rename to match your kdf.py


IKM = b"\x01" * 32


def test_deterministic():
    assert derive(IKM, b"ctx") == derive(IKM, b"ctx")


def test_different_context_gives_different_key():
    assert derive(IKM, b"ctx-a") != derive(IKM, b"ctx-b")


def test_different_input_gives_different_key():
    assert derive(IKM, b"ctx") != derive(b"\x02" * 32, b"ctx")


def test_output_is_32_bytes():
    assert len(derive(IKM, b"ctx")) == 32