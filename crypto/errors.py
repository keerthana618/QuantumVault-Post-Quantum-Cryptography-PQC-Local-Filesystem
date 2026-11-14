"""Custom exceptions for the project cryptographic interfaces."""


class CryptoError(RuntimeError):
    """Base exception for all vault crypto errors."""


class CryptoConfigurationError(CryptoError):
    """Raised when a backend or algorithm configuration is invalid."""


class KEMNotAvailableError(CryptoError):
    """Raised when a KEM backend is unavailable on the host machine."""


class UnsupportedAlgorithmError(CryptoConfigurationError):
    """Raised when a requested key-encapsulation mechanism is unsupported."""


class InvalidKeyError(CryptoError):
    """Raised when key material does not match the expected format."""


class EncapsulationError(CryptoError):
    """Raised when a KEM encapsulation step fails."""


class DecapsulationError(CryptoError):
    """Raised when a KEM decapsulation step fails."""


class KEMCheckFailedError(CryptoError):
    """Raised when a liboqs/KEM verification check fails."""


__all__ = [
    "CryptoError",
    "CryptoConfigurationError",
    "KEMNotAvailableError",
    "UnsupportedAlgorithmError",
    "InvalidKeyError",
    "EncapsulationError",
    "DecapsulationError",
    "KEMCheckFailedError",
]
