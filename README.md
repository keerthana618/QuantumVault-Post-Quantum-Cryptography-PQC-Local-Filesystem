# QuantumVault-Post-Quantum-Cryptography-PQC-Local-Filesystem

This project is a local-filesystem vault that uses post-quantum cryptography to protect file keys and encrypted data. The current setup phase covers the liboqs runtime and the project-level crypto abstractions.

## Section 4 setup

1. Build liboqs with the included helper script:
   `bash scripts/build_liboqs.sh`
2. Confirm that the KEM export is present with:
   `python scripts/check_liboqs_kem.py`
3. Use the crypto package stubs in `crypto/` as the interface layer for the later KEM and KDF implementations.

## Crypto interfaces

The `crypto` package contains the project-defined exceptions and abstract interfaces used by future ML-KEM and AES-backed code paths.
