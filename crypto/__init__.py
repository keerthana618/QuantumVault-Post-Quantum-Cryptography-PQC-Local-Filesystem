"""Public crypto package exports for the local filesystem vault."""

from .errors import (
    CryptoConfigurationError,
    CryptoError,
    DecapsulationError,
    DecryptionError,
    EncapsulationError,
    InvalidKeyError,
    InvalidNonceError,
    KEMCheckFailedError,
    KEMNotAvailableError,
    KEMUnavailableError,
    KeyDerivationError,
    KeystoreError,
    SignatureBackendError,
    SigningError,
    UnsupportedAlgorithmError,
    WrongPasswordError,
)
from .interfaces import KeyDerivationFunction, KeyEncapsulationMechanism, SymmetricCipher
from .kem import KEMFactory, MLKEM
from .filevault import (
    decrypt_file,
    decrypt_file_bytes,
    encrypt_file,
    encrypt_file_bytes,
)

__all__ = [
    "CryptoError",
    "CryptoConfigurationError",
    "KEMNotAvailableError",
    "KEMUnavailableError",
    "UnsupportedAlgorithmError",
    "InvalidKeyError",
    "InvalidNonceError",
    "DecryptionError",
    "KeyDerivationError",
    "KeystoreError",
    "WrongPasswordError",
    "EncapsulationError",
    "DecapsulationError",
    "KEMCheckFailedError",
    "SigningError",
    "SignatureBackendError",
    "KeyEncapsulationMechanism",
    "KeyDerivationFunction",
    "SymmetricCipher",
    "MLKEM",
    "KEMFactory",
    "encrypt_file",
    "encrypt_file_bytes",
    "decrypt_file",
    "decrypt_file_bytes",
]
