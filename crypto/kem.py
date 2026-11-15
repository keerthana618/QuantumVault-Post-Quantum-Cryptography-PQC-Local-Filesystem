
from __future__ import annotations

from typing import Iterable, Tuple

from .errors import UnsupportedAlgorithmError
from .interfaces import KeyEncapsulationMechanism


class MLKEM(KeyEncapsulationMechanism):
    """Stub implementation for a liboqs-backed ML-KEM algorithm."""

    algorithm_name = "ML-KEM"

    @classmethod
    def supported_algorithms(cls) -> Iterable[str]:
        return ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        raise NotImplementedError("A liboqs-backed ML-KEM implementation will be added in a later section.")

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        self._assert_valid_public_key(public_key)
        raise NotImplementedError("KEM encapsulation is not implemented yet.")

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        self._assert_valid_secret_key(secret_key)
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("ciphertext must be bytes-like.")
        raise NotImplementedError("KEM decapsulation is not implemented yet.")


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
        return implementation()


__all__ = ["MLKEM", "KEMFactory"]
