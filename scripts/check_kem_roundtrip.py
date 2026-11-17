"""Real KEM check: keygen -> encapsulate -> decapsulate for every ML-KEM variant.

Run from the repo root:  python scripts/check_kem_roundtrip.py
Exit code is 0 only if every variant passes.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.kem import ALL_VARIANTS, MLKEM  # noqa: E402
from crypto.errors import KEMUnavailableError  # noqa: E402


def check(variant: str) -> None:
    kem = MLKEM(variant)
    public_key, secret_key = kem.generate_keypair()
    ciphertext, secret_sender = kem.encapsulate(public_key)
    secret_receiver = kem.decapsulate(secret_key, ciphertext)

    assert len(public_key) == kem.sizes.public_key, "public key size mismatch"
    assert len(secret_key) == kem.sizes.secret_key, "secret key size mismatch"
    assert len(ciphertext) == kem.sizes.ciphertext, "ciphertext size mismatch"
    assert len(secret_sender) == kem.sizes.shared_secret, "shared secret size mismatch"
    assert secret_sender == secret_receiver, "shared secrets do not match"

    note = "" if kem.is_final_standard else "  (pre-standard Kyber, not FIPS 203)"
    print(
        f"PASS {variant}  mechanism={kem.mechanism}  "
        f"pk={len(public_key)}  ct={len(ciphertext)}  ss={len(secret_sender)}{note}"
    )


def main() -> int:
    failed = False
    for variant in ALL_VARIANTS:
        try:
            check(variant)
        except KEMUnavailableError as exc:
            failed = True
            print(f"FAIL {variant}: KEM unavailable: {exc}")
        except Exception as exc:
            failed = True
            print(f"FAIL {variant}: {type(exc).__name__}: {exc}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
