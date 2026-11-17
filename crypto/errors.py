import hashlib
import secrets
from dataclasses import dataclass


class CryptoError(RuntimeError):
    """Base exception for all vault crypto errors."""


class CryptoConfigurationError(CryptoError):
    """Raised when a backend or algorithm configuration is invalid."""


class KEMNotAvailableError(CryptoError):
    """Raised when a KEM backend is unavailable on the host machine."""


class KEMUnavailableError(KEMNotAvailableError):
    """Compatibility alias for backend unavailability errors in liboqs-backed KEM code."""


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


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
Q = 3329          # prime modulus
N = 256           # polynomial length
INV_128 = 3303    # 128^-1 mod Q


@dataclass(frozen=True)
class Params:
    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int

    @property
    def ek_size(self):
        return 384 * self.k + 32

    @property
    def dk_size(self):
        return 768 * self.k + 96

    @property
    def ct_size(self):
        return 32 * (self.du * self.k + self.dv)


PARAMS = {
    "ML-KEM-512": Params("ML-KEM-512", 2, 3, 2, 10, 4),
    "ML-KEM-768": Params("ML-KEM-768", 3, 2, 2, 10, 4),
    "ML-KEM-1024": Params("ML-KEM-1024", 4, 2, 2, 11, 5),
}


def _get_params(params):
    if isinstance(params, Params):
        return params
    try:
        return PARAMS[params]
    except KeyError:
        raise ValueError(f"Unknown parameter set: {params!r}. "
                         f"Choose from {list(PARAMS)}")


__all__ = [
    "CryptoError",
    "CryptoConfigurationError",
    "KEMNotAvailableError",
    "KEMUnavailableError",
    "UnsupportedAlgorithmError",
    "InvalidKeyError",
    "EncapsulationError",
    "DecapsulationError",
    "KEMCheckFailedError",
    "Params",
    "PARAMS",
    "_get_params",
]
