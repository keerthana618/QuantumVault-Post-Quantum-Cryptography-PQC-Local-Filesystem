"""Abstract interfaces that model the cryptographic operations the vault uses."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Tuple

from .errors import CryptoConfigurationError, InvalidKeyError


class KeyEncapsulationMechanism(ABC):
    """Base interface for a post-quantum key-encapsulation scheme."""

    algorithm_name: str = ""

    @classmethod
    @abstractmethod
    def supported_algorithms(cls) -> Iterable[str]:
        """Return known algorithm names for the implementation."""

    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a public/secret keypair for this KEM."""

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret) for the supplied public key."""

    @abstractmethod
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Recover the shared secret from the supplied secret key/ciphertext."""

    def validate(self) -> None:
        """Simple sanity check for a configured implementation."""
        if not self.algorithm_name:
            raise CryptoConfigurationError("KEM algorithm name is not configured.")

    def _assert_valid_public_key(self, public_key: bytes) -> None:
        if not isinstance(public_key, (bytes, bytearray)):
            raise InvalidKeyError("public_key must be bytes-like.")

    def _assert_valid_secret_key(self, secret_key: bytes) -> None:
        if not isinstance(secret_key, (bytes, bytearray)):
            raise InvalidKeyError("secret_key must be bytes-like.")


class KeyDerivationFunction(ABC):
    """Abstract interface for KDFs used after KEM negotiation."""

    algorithm_name: str = ""

    @classmethod
    @abstractmethod
    def supported_algorithms(cls) -> Iterable[str]:
        """Return supported KDF identifiers."""

    @abstractmethod
    def derive(self, secret: bytes, salt: bytes | None = None, info: bytes | None = None) -> bytes:
        """Derive a key from shared secret material."""


class SymmetricCipher(ABC):
    """Abstract interface for the symmetric primitive that wraps file keys."""

    algorithm_name: str = ""

    @classmethod
    @abstractmethod
    def supported_algorithms(cls) -> Iterable[str]:
        """Return supported cipher identifiers."""

    @abstractmethod
    def encrypt(self, key: bytes, data: bytes) -> bytes:
        """Encrypt data under a symmetric key."""

    @abstractmethod
    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext under a symmetric key."""


__all__ = [
    "KeyEncapsulationMechanism",
    "KeyDerivationFunction",
    "SymmetricCipher",
]
