
"""ML-DSA (FIPS 204) digital signatures, backed by liboqs.
 
Key and signature sizes are read from liboqs at runtime, not typed in by hand.
"""
 
from __future__ import annotations
 
from dataclasses import dataclass
 
# SigningError and SignatureBackendError are added by scripts/add_sig_errors.py.
from crypto.errors import (
    InvalidKeyError,
    SignatureBackendError,
    SigningError,
    UnsupportedAlgorithmError,
    )
 
try:
    import oqs
 
    _OQS_IMPORT_ERROR = None
except Exception as exc:  # package missing, or liboqs shared library not found
    oqs = None
    _OQS_IMPORT_ERROR = exc
 
# Newer liboqs builds name these ML-DSA-*. Older builds only have the
# pre-standard Dilithium* versions, which are NOT identical to FIPS 204.
_MECHANISM_NAMES = {
    "ML-DSA-44": ("ML-DSA-44", "Dilithium2"),
    "ML-DSA-65": ("ML-DSA-65", "Dilithium3"),
    "ML-DSA-87": ("ML-DSA-87", "Dilithium5"),
}
 
ALL_VARIANTS = tuple(_MECHANISM_NAMES)
DEFAULT_VARIANT = "ML-DSA-65"
MAX_CONTEXT_BYTES = 255  # FIPS 204 limit for the context string
 
 
def _require_oqs() -> None:
    if oqs is None:
        raise SignatureBackendError(
            f"liboqs-python could not be loaded: {_OQS_IMPORT_ERROR}"
        )
 
 
def _resolve_mechanism(variant: str) -> str:
    if variant not in _MECHANISM_NAMES:
        raise UnsupportedAlgorithmError(
            f"Unknown variant {variant!r}. Use one of {list(ALL_VARIANTS)}."
        )
    _require_oqs()
    enabled = set(oqs.get_enabled_sig_mechanisms())
    for name in _MECHANISM_NAMES[variant]:
        if name in enabled:
            return name
    raise UnsupportedAlgorithmError(f"{variant} is not enabled in this liboqs build.")
 
 
def supported_variants() -> list[str]:
    """Variants that the installed liboqs build can actually run."""
    found = []
    for variant in ALL_VARIANTS:
        try:
            _resolve_mechanism(variant)
        except (UnsupportedAlgorithmError, SignatureBackendError):
            continue
        found.append(variant)
    return found
 
 
@dataclass(frozen=True)
class SigSizes:
    public_key: int
    secret_key: int
    signature: int
 
 
def _as_bytes(label: str, value, error_cls) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise error_cls(f"{label} must be bytes, got {type(value).__name__}.")
    return bytes(value)
 
 
class MLDSA:
    """ML-DSA signatures for one parameter set."""
 
    def __init__(self, variant: str = DEFAULT_VARIANT):
        self.variant = variant
        self.mechanism = _resolve_mechanism(variant)
        try:
            with oqs.Signature(self.mechanism) as sig:
                d = sig.details
                self.sizes = SigSizes(
                    public_key=int(d["length_public_key"]),
                    secret_key=int(d["length_secret_key"]),
                    signature=int(d["length_signature"]),
                )
        except Exception as exc:
            raise SignatureBackendError(
                f"Could not read {self.mechanism} details from liboqs: {exc}"
            ) from exc
        # Context strings need a recent liboqs-python.
        self.supports_context = hasattr(oqs.Signature, "sign_with_ctx_str")
 
    @property
    def is_final_standard(self) -> bool:
        """False if liboqs only offers the older pre-standard Dilithium names."""
        return self.mechanism.startswith("ML-DSA")
 
    def _check_key(self, label: str, value, expected: int) -> bytes:
        value = _as_bytes(label, value, InvalidKeyError)
        if len(value) != expected:
            raise InvalidKeyError(f"{label} must be {expected} bytes, got {len(value)}.")
        return value
 
    def _check_context(self, context, error_cls) -> bytes:
        context = _as_bytes("context", context, error_cls)
        if len(context) > MAX_CONTEXT_BYTES:
            raise error_cls(f"context must be at most {MAX_CONTEXT_BYTES} bytes.")
        if context and not self.supports_context:
            raise SignatureBackendError(
                "This liboqs-python version does not support context strings. "
                "Upgrade it, or call without a context."
            )
        return context
 
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""
        try:
            with oqs.Signature(self.mechanism) as sig:
                public_key = bytes(sig.generate_keypair())
                secret_key = bytes(sig.export_secret_key())
        except Exception as exc:
            raise SignatureBackendError(f"Key generation failed: {exc}") from exc
        return public_key, secret_key
 
    def sign(self, secret_key: bytes, message: bytes, context: bytes = b"") -> bytes:
        """Return a signature over message.
 
        context is an optional label (for example b"quantumvault-vault-header-v1")
        that separates signatures made for different purposes.
        """
        secret_key = self._check_key("secret key", secret_key, self.sizes.secret_key)
        message = _as_bytes("message", message, SigningError)
        context = self._check_context(context, SigningError)
        try:
            with oqs.Signature(self.mechanism, secret_key) as signer:
                if context:
                    signature = signer.sign_with_ctx_str(message, context)
                else:
                    signature = signer.sign(message)
        except Exception as exc:
            raise SigningError(f"Signing failed: {exc}") from exc
        return bytes(signature)
 
    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes = b"",
    ) -> bool:
        """Return True only if the signature is valid. Never raises for a bad signature.
 
        Bad keys and bad input types raise errors. A wrong signature, a wrong
        length signature, or any verification failure returns False.
        """
        public_key = self._check_key("public key", public_key, self.sizes.public_key)
        message = _as_bytes("message", message, SigningError)
        signature = _as_bytes("signature", signature, SigningError)
        context = self._check_context(context, SigningError)
        if len(signature) != self.sizes.signature:
            return False
        try:
            with oqs.Signature(self.mechanism) as verifier:
                if context:
                    ok = verifier.verify_with_ctx_str(message, signature, context, public_key)
                else:
                    ok = verifier.verify(message, signature, public_key)
        except Exception:
            return False  # fail closed
        return bool(ok)
 
 
def get_signer(variant: str = DEFAULT_VARIANT) -> MLDSA:
    """Factory: return an MLDSA object for the chosen parameter set."""
    return MLDSA(variant)
 