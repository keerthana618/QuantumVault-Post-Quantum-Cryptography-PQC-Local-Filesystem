import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

LIB_DIR = ROOT / ".vendor" / "liboqs" / "build" / "bin"
if LIB_DIR.exists():
    os.environ.setdefault("LIBOQS_LIBRARY", str(LIB_DIR))
    os.environ["PATH"] = str(LIB_DIR) + os.pathsep + os.environ.get("PATH", "")

import oqs

from crypto.errors import InvalidKeyError, KEMUnavailableError, UnsupportedAlgorithmError
from crypto.kem import MLKEM, ALL_VARIANTS, KEMFactory, supported_variants


def test_oqs_import_and_available_algorithms() -> None:
    enabled = set(oqs.get_enabled_kem_mechanisms())
    assert {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}.issubset(enabled)


def test_ml_kem_roundtrip_for_all_supported_variants() -> None:
    variants = supported_variants() or list(ALL_VARIANTS)
    for variant in variants:
        kem = MLKEM(variant)
        public_key, secret_key = kem.generate_keypair()
        ciphertext, sender_secret = kem.encapsulate(public_key)
        receiver_secret = kem.decapsulate(secret_key, ciphertext)

        assert len(public_key) == kem.sizes.public_key
        assert len(secret_key) == kem.sizes.secret_key
        assert len(ciphertext) == kem.sizes.ciphertext
        assert len(sender_secret) == kem.sizes.shared_secret
        assert sender_secret == receiver_secret


def test_invalid_inputs_are_rejected() -> None:
    kem = MLKEM("ML-KEM-768")
    with pytest.raises(InvalidKeyError):
        kem.encapsulate(b"not a valid public key")

    with pytest.raises(InvalidKeyError):
        kem.decapsulate(b"not a valid secret key", b"not a valid ciphertext")


def test_unknown_algorithm_is_rejected() -> None:
    with pytest.raises(UnsupportedAlgorithmError):
        KEMFactory.create("ML-KEM-4096")


def test_missing_backend_raises_clear_error() -> None:
    original = oqs
    try:
        import crypto.kem as kem_module

        kem_module.oqs = None
        with pytest.raises(KEMUnavailableError):
            MLKEM("ML-KEM-768")
    finally:
        kem_module.oqs = original
