"""Concrete KEM scaffolding used by the vault implementation."""

from __future__ import annotations

from typing import Iterable, Tuple

from .errors import UnsupportedAlgorithmError
from .interfaces import KeyEncapsulationMechanism

try:
    import oqs  # liboqs-python
except Exception:  # liboqs not installed; error is raised when a method is used
    oqs = None

# FIPS 203 sizes in bytes, used to check inputs before calling liboqs.
_SIZES = {
    "ML-KEM-512": {"public_key": 800, "secret_key": 1632, "ciphertext": 768},
    "ML-KEM-768": {"public_key": 1184, "secret_key": 2400, "ciphertext": 1088},
    "ML-KEM-1024": {"public_key": 1568, "secret_key": 3168, "ciphertext": 1568},
}
_SHARED_SECRET_SIZE = 32
_DEFAULT = "ML-KEM-768"
# Older liboqs versions call the same schemes Kyber.
_LEGACY = {"ML-KEM-512": "Kyber512", "ML-KEM-768": "Kyber768", "ML-KEM-1024": "Kyber1024"}


class MLKEM(KeyEncapsulationMechanism):
    """liboqs-backed ML-KEM algorithm."""

    algorithm_name = "ML-KEM"

    def __init__(self, parameter_set: str = _DEFAULT) -> None:
        super().__init__()
        if parameter_set == self.algorithm_name:
            parameter_set = _DEFAULT
        if parameter_set not in _SIZES:
            raise UnsupportedAlgorithmError(f"Unsupported KEM algorithm: {parameter_set}")
        self.parameter_set = parameter_set

    @classmethod
    def supported_algorithms(cls) -> Iterable[str]:
        return ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")

    def _oqs_name(self) -> str:
        if oqs is None:
            raise RuntimeError("liboqs-python is not installed. Run: pip install liboqs-python")
        enabled = set(oqs.get_enabled_kem_mechanisms())
        for name in (self.parameter_set, _LEGACY[self.parameter_set]):
            if name in enabled:
                return name
        raise UnsupportedAlgorithmError(f"{self.parameter_set} is not enabled in this liboqs build.")

    def _check_length(self, data: bytes, kind: str) -> None:
        expected = _SIZES[self.parameter_set][kind]
        if len(data) != expected:
            raise ValueError(
                f"{kind} for {self.parameter_set} must be {expected} bytes, got {len(data)}."
            )

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""
        with oqs.KeyEncapsulation(self._oqs_name()) as kem:
            public_key = bytes(kem.generate_keypair())
            secret_key = bytes(kem.export_secret_key())
        return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret)."""
        self._assert_valid_public_key(public_key)
        public_key = bytes(public_key)
        self._check_length(public_key, "public_key")
        with oqs.KeyEncapsulation(self._oqs_name()) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Return the 32-byte shared secret."""
        self._assert_valid_secret_key(secret_key)
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("ciphertext must be bytes-like.")
        secret_key, ciphertext = bytes(secret_key), bytes(ciphertext)
        self._check_length(secret_key, "secret_key")
        self._check_length(ciphertext, "ciphertext")
        with oqs.KeyEncapsulation(self._oqs_name(), secret_key) as kem:
            return bytes(kem.decap_secret(ciphertext))


class KEMFactory:
    """Factory used to resolve a supported KEM implementation."""

    _registry = {
        "ML-KEM": MLKEM,
        "ML-KEM-512": MLKEM,
        "ML-KEM-768": MLKEM,
        "ML-KEM-1024": MLKEM,
    }

    @classmethod
    def create(cls, algorithm_name: str) -> KeyEncapsulationMechanism:
        implementation = cls._registry.get(algorithm_name)
        if implementation is None:
            raise UnsupportedAlgorithmError(f"Unsupported KEM algorithm: {algorithm_name}")
        return implementation(algorithm_name)


__all__ = ["MLKEM", "KEMFactory"]
