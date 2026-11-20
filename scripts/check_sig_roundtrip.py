
"""Real signature check: keygen -> sign -> verify for every ML-DSA variant.
 
Run from the repo root:  python scripts/check_sig_roundtrip.py
Exit code is 0 only if every variant passes.
"""
 
import sys
from pathlib import Path
 
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
 
from crypto.sig import ALL_VARIANTS, MLDSA  # noqa: E402
 
MESSAGE = b"QuantumVault signature check"
 
 
def check(variant: str) -> None:
    signer = MLDSA(variant)
    public_key, secret_key = signer.generate_keypair()
    signature = signer.sign(secret_key, MESSAGE)
 
    assert len(public_key) == signer.sizes.public_key, "public key size mismatch"
    assert len(secret_key) == signer.sizes.secret_key, "secret key size mismatch"
    assert len(signature) == signer.sizes.signature, "signature size mismatch"
    assert signer.verify(public_key, MESSAGE, signature) is True, "valid signature rejected"
    assert signer.verify(public_key, MESSAGE + b"x", signature) is False, "tampered message accepted"
 
    note = "" if signer.is_final_standard else "  (pre-standard Dilithium, not FIPS 204)"
    print(
        f"PASS {variant}  mechanism={signer.mechanism}  "
        f"pk={len(public_key)}  sk={len(secret_key)}  sig={len(signature)}{note}"
    )
 
 
def main() -> int:
    failed = False
    for variant in ALL_VARIANTS:
        try:
            check(variant)
        except Exception as exc:
            failed = True
            print(f"FAIL {variant}: {type(exc).__name__}: {exc}")
    return 1 if failed else 0
 
 
if __name__ == "__main__":
    sys.exit(main())
 