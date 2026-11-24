# QuantumVault-Post-Quantum-Cryptography-PQC-Local-Filesystem

QuantumVault is a Python cryptography prototype for a local-filesystem vault. It combines NIST-standardized post-quantum primitives with authenticated symmetric encryption and password-derived key storage.

## Implemented components

- **ML-KEM**: ML-KEM-512, ML-KEM-768, and ML-KEM-1024 key encapsulation through `liboqs`
- **ML-DSA**: ML-DSA-44, ML-DSA-65, and ML-DSA-87 digital signatures through `liboqs`
- **AES-256-GCM**: random-nonced authenticated encryption with optional AAD
- **HKDF-SHA256**: RFC 5869 key derivation for strong input key material
- **Argon2id keystore**: password-protected private-key storage with AES-256-GCM
- **File envelope**: versioned ML-KEM + HKDF-SHA256 + AES-256-GCM encrypted file blobs
- **Error handling**: normalized cryptographic exceptions for invalid keys, unavailable backends, and decryption failures

The cryptographic modules are in `crypto/`. Unit tests are in `tests/`, and native backend round-trip checks are in `scripts/`.

## Requirements

- Python 3.10 or newer
- `liboqs` shared library enabled for ML-KEM and ML-DSA
- Windows, Linux, or macOS capable of running the native `liboqs` backend

Python dependencies are listed in `requirements.txt`:

```text
liboqs-python==0.16.0.2
pytest>=8.0
cryptography>=46.0
argon2-cffi>=25.1
```

## Setup

Create and activate a virtual environment.

Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The `liboqs-python` package requires a compatible native `liboqs` runtime. If a system package or shared library is unavailable, build `liboqs` with the ML-KEM and ML-DSA algorithms you need, then expose the shared-library directory to the process through `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, or `LIBOQS_LIBRARY` and `PATH` as appropriate for the platform.

The repository includes `scripts/build_liboqs.sh` for Linux-style environments.

## Verification

Run the unit test suite:

```bash
python -m pytest -q
```

Run native ML-KEM checks:

```bash
python scripts/check_liboqs_kem.py
python scripts/check_kem_roundtrip.py
```

Run native ML-DSA checks:

```bash
python scripts/check_sig_roundtrip.py
```

Use `python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"` to inspect available ML-KEM mechanisms and `python -c "import oqs; print(oqs.get_enabled_sig_mechanisms())"` to inspect available ML-DSA mechanisms.

## Project status

The ML-KEM, ML-DSA, AES-GCM, HKDF-SHA256, password-protected keystore, and file-envelope layers have working implementations and tests. ML-KEM and ML-DSA round-trip checks pass against the native standardized mechanisms in the configured liboqs build.

This repository is a cryptographic component prototype, not yet a complete production vault application. A higher-level file vault workflow, metadata format, secure CLI or GUI, key lifecycle management, backup and recovery, and hardened end-to-end integration are not yet implemented.
