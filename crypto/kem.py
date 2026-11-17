"""ML-KEM (FIPS 203) key encapsulation backed by liboqs.

The project intentionally distinguishes the standardized ML-KEM names from
legacy pre-standard Kyber names. Older Kyber algorithms are compatibility
aliases only and are not equivalent to FIPS 203 ML-KEM.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from crypto.errors import (
    DecapsulationError,
    EncapsulationError,
    InvalidKeyError,
    KEMUnavailableError,
    UnsupportedAlgorithmError,
)
from crypto.interfaces import KeyEncapsulationMechanism

try:
    import oqs  # type: ignore
except Exception as exc:  # pragma: no cover - import-time backend detection
    oqs = None
    _OQS_IMPORT_ERROR = exc
else:
    _OQS_IMPORT_ERROR = None


def _ensure_native_toolchain() -> None:
    """Add common Windows toolchain locations to PATH when liboqs needs to build."""
    candidates = []
    for raw in (
        os.environ.get("PATH", ""),
        os.environ.get("CMAKE_PREFIX_PATH", ""),
        os.environ.get("CMAKE_PROGRAM_PATH", ""),
    ):
        for part in raw.split(os.pathsep):
            if part:
                candidates.append(part)
    candidates.extend(
        [
            r"C:\Program Files\CMake\bin",
            r"C:\Program Files\Git\bin",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC",
            r"C:\Android\Sdk\cmake\3.22.1\bin",
        ]
    )
    seen = set()
    path_entries = []
    for candidate in candidates:
        full = str(Path(candidate).expanduser())
        if not full or full in seen:
            continue
        seen.add(full)
        if Path(full).exists():
            path_entries.append(full)
    if path_entries:
        os.environ["PATH"] = os.pathsep.join(path_entries + [os.environ.get("PATH", "")])

    if not os.environ.get("CC"):
        cl_path = shutil.which("cl")
        if cl_path:
            os.environ["CC"] = cl_path
            os.environ["CXX"] = cl_path
    if not os.environ.get("CMAKE_MAKE_PROGRAM"):
        ninja_path = shutil.which("ninja") or str(Path(r"C:\Android\Sdk\cmake\3.22.1\bin\ninja.exe"))
        if Path(ninja_path).exists():
            os.environ["CMAKE_MAKE_PROGRAM"] = ninja_path


_ensure_native_toolchain()

_SIZES = {
    "ML-KEM-512": {"public_key": 800, "secret_key": 1632, "ciphertext": 768},
    "ML-KEM-768": {"public_key": 1184, "secret_key": 2400, "ciphertext": 1088},
    "ML-KEM-1024": {"public_key": 1568, "secret_key": 3168, "ciphertext": 1568},
}
_DEFAULT = "ML-KEM-768"
_LEGACY = {"ML-KEM-512": "Kyber512", "ML-KEM-768": "Kyber768", "ML-KEM-1024": "Kyber1024"}
_MECHANISM_NAMES = {
    "ML-KEM-512": ("ML-KEM-512", "Kyber512"),
    "ML-KEM-768": ("ML-KEM-768", "Kyber768"),
    "ML-KEM-1024": ("ML-KEM-1024", "Kyber1024"),
}
ALL_VARIANTS = tuple(_MECHANISM_NAMES)
DEFAULT_VARIANT = "ML-KEM-768"


def _require_oqs() -> None:
    if oqs is None:
        raise KEMUnavailableError(f"liboqs-python could not be loaded: {_OQS_IMPORT_ERROR}")


def _resolve_mechanism(variant: str) -> str:
    if variant not in _MECHANISM_NAMES:
        raise UnsupportedAlgorithmError(
            f"Unknown variant {variant!r}. Use one of {list(ALL_VARIANTS)}."
        )
    _require_oqs()
    enabled = set(oqs.get_enabled_kem_mechanisms())
    for candidate in _MECHANISM_NAMES[variant]:
        if candidate in enabled:
            return candidate
    raise UnsupportedAlgorithmError(f"{variant} is not enabled in this liboqs build.")


def supported_variants() -> list[str]:
    """Return the ML-KEM parameter sets that the active liboqs backend can run."""
    found: list[str] = []
    for variant in ALL_VARIANTS:
        try:
            _resolve_mechanism(variant)
        except (UnsupportedAlgorithmError, KEMUnavailableError):
            continue
        found.append(variant)
    return found


@dataclass(frozen=True)
class KEMSizes:
    public_key: int
    secret_key: int
    ciphertext: int
    shared_secret: int


class MLKEM(KeyEncapsulationMechanism):
    """liboqs-backed ML-KEM implementation for one parameter set."""

    algorithm_name = DEFAULT_VARIANT

    def __init__(self, variant: str = DEFAULT_VARIANT):
        self.variant = variant
        self.mechanism = _resolve_mechanism(variant)
        self.algorithm_name = variant
        try:
            with oqs.KeyEncapsulation(self.mechanism) as kem:
                details = kem.details
                self.sizes = KEMSizes(
                    public_key=int(details["length_public_key"]),
                    secret_key=int(details["length_secret_key"]),
                    ciphertext=int(details["length_ciphertext"]),
                    shared_secret=int(details["length_shared_secret"]),
                )
        except Exception as exc:  # pragma: no cover - backend returns a runtime error
            raise KEMUnavailableError(
                f"Could not read {self.mechanism} details from liboqs: {exc}"
            ) from exc

    @classmethod
    def supported_algorithms(cls) -> Iterable[str]:
        return ALL_VARIANTS

    @property
    def is_final_standard(self) -> bool:
        """False only when a legacy Kyber name is selected in a pre-standard build."""
        return self.mechanism.startswith("ML-KEM")

    @staticmethod
    def _check(label: str, value: bytes | bytearray | memoryview, expected: int, error_cls):
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise error_cls(f"{label} must be bytes, got {type(value).__name__}.")
        value = bytes(value)
        if len(value) != expected:
            raise error_cls(f"{label} must be {expected} bytes, got {len(value)}.")
        return value

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""
        try:
            with oqs.KeyEncapsulation(self.mechanism) as kem:
                public_key = bytes(kem.generate_keypair())
                secret_key = bytes(kem.export_secret_key())
        except Exception as exc:
            raise KEMUnavailableError(f"Key generation failed: {exc}") from exc
        return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret) for the given public key."""
        public_key = self._check("public key", public_key, self.sizes.public_key, InvalidKeyError)
        try:
            with oqs.KeyEncapsulation(self.mechanism) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)
        except Exception as exc:
            raise EncapsulationError(f"Encapsulation failed: {exc}") from exc
        return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Return the shared secret for a valid key/ciphertext pair."""
        secret_key = self._check("secret key", secret_key, self.sizes.secret_key, InvalidKeyError)
        ciphertext = self._check("ciphertext", ciphertext, self.sizes.ciphertext, DecapsulationError)
        try:
            with oqs.KeyEncapsulation(self.mechanism, secret_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
        except Exception as exc:
            raise DecapsulationError(f"Decapsulation failed: {exc}") from exc
        return bytes(shared_secret)


class KEMFactory:
    """Factory used to resolve a supported liboqs-backed ML-KEM implementation."""

    _registry = {
        "ML-KEM": DEFAULT_VARIANT,
        "ML-KEM-512": "ML-KEM-512",
        "ML-KEM-768": "ML-KEM-768",
        "ML-KEM-1024": "ML-KEM-1024",
    }

    @classmethod
    def create(cls, variant: str = DEFAULT_VARIANT) -> MLKEM:
        normalized = cls._registry.get(variant, variant)
        return MLKEM(normalized)


def get_kem(variant: str = DEFAULT_VARIANT) -> MLKEM:
    """Factory helper returning an MLKEM wrapper for the requested variant."""
    return MLKEM(variant)
