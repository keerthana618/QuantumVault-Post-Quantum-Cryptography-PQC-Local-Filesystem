"""Password-protected private-key storage (Argon2id + AES-256-GCM)."""
import base64
import json
import os

from argon2.low_level import Type, hash_secret_raw

from .aead import decrypt, encrypt
from .errors import DecryptionError, KeystoreError, WrongPasswordError
 
FORMAT_VERSION = 1
SALT_BYTES = 16
KEY_BYTES = 32
 
# Argon2id parameters (stored in the file so they can be raised later)
DEFAULT_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
 
 
def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")
 
 
def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))
 
 
def _to_bytes(password) -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")
    if not isinstance(password, (bytes, bytearray)) or len(password) == 0:
        raise KeystoreError("Password must be a non-empty string or bytes.")
    return bytes(password)
 
 
def derive_key(password, salt: bytes, params: dict | None = None) -> bytes:
    """Derive a 32-byte key from a password using Argon2id."""
    p = params or DEFAULT_PARAMS
    return hash_secret_raw(
        secret=_to_bytes(password),
        salt=salt,
        time_cost=p["time_cost"],
        memory_cost=p["memory_cost"],
        parallelism=p["parallelism"],
        hash_len=KEY_BYTES,
        type=Type.ID,
    )
 
 
def _header_aad(version: int, salt: bytes, params: dict) -> bytes:
    """Bind header fields to the ciphertext so tampering is detected."""
    return json.dumps(
        {"v": version, "salt": _b64e(salt), "params": params}, sort_keys=True
    ).encode("utf-8")
 
 
def save_private_key(path: str, private_key: bytes, password, params: dict | None = None) -> None:
    """Encrypt private_key with a password and write it to path (mode 600)."""
    params = dict(params or DEFAULT_PARAMS)
    salt = os.urandom(SALT_BYTES)
    key = derive_key(password, salt, params)
    blob = encrypt(key, bytes(private_key), _header_aad(FORMAT_VERSION, salt, params))
 
    doc = {
        "version": FORMAT_VERSION,
        "kdf": "argon2id",
        "salt": _b64e(salt),
        "params": params,
        "blob": _b64e(blob),
    }
 
    # Create with 600 from the start (no window where it is world-readable)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)
    os.chmod(path, 0o600)
 
 
def load_private_key(path: str, password) -> bytes:
    """Read and decrypt a private key. Raises WrongPasswordError on bad password."""
    try:
        with open(path, "r") as f:
            doc = json.load(f)
        version = doc["version"]
        salt = _b64d(doc["salt"])
        params = doc["params"]
        blob = _b64d(doc["blob"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise KeystoreError(f"Could not read key file: {path}") from exc
 
    if version != FORMAT_VERSION:
        raise KeystoreError(f"Unsupported key file version: {version}")
 
    key = derive_key(password, salt, params)
    try:
        return decrypt(key, blob, _header_aad(version, salt, params))
    except DecryptionError as exc:
        raise WrongPasswordError("Wrong password or corrupted key file.") from exc
 