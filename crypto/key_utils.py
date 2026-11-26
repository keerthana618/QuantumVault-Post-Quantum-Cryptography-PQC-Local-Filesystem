import secrets
import hashlib

from .errors import InvalidKeyError


AES_KEY_SIZE = 32


def generate_aes_key():
    """Generate a secure random 256-bit AES key."""
    return secrets.token_bytes(AES_KEY_SIZE)


def validate_aes_key(key):
    """Validate AES-256 key length."""
    if not isinstance(key, bytes):
        raise InvalidKeyError("AES key must be bytes")

    if len(key) != AES_KEY_SIZE:
        raise InvalidKeyError("AES-256 requires a 32-byte key")

    return True


def generate_key_fingerprint(key):
    """Generate SHA-256 fingerprint of a key."""
    validate_aes_key(key)

    return hashlib.sha256(key).hexdigest()


def compare_key_fingerprints(key1, key2):
    """Compare two AES keys using constant-time comparison."""
    validate_aes_key(key1)
    validate_aes_key(key2)

    return secrets.compare_digest(
        generate_key_fingerprint(key1),
        generate_key_fingerprint(key2)
    )
