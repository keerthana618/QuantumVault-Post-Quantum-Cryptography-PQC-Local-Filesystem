# Day 1: Why quantum computers threaten public-key cryptography

## What RSA and elliptic curves rely on

- Public-key cryptography supports key establishment (agreeing on secret key material over an open network) and digital signatures (checking who signed data and whether it changed).
- RSA's security relies on the practical difficulty of factoring a product of large primes; its public key includes that product.
- ECDH and ECDSA rely on the difficulty of the elliptic-curve discrete-logarithm problem: recovering a private scalar from its public curve point.
- AES is a symmetric cipher and SHA-256 is a hash function; neither depends on factoring or elliptic-curve discrete logs.

## What quantum algorithms change

- Shor's algorithm would let a sufficiently large, fault-tolerant quantum computer factor RSA moduli and solve elliptic-curve discrete logs efficiently, undermining RSA, ECDH, and ECDSA at cryptographic sizes.
- Grover's algorithm gives an idealized quadratic speedup for unstructured key search. Against AES-256, that is often described as roughly 128-bit quantum search strength, still beyond practical reach; it is not a break of AES like Shor is for RSA/ECC.
- No known quantum computer can run Shor's algorithm at cryptographically relevant scale today. This is a future-capability risk, not a claim that current machines can decrypt these keys.

## Harvest now, decrypt later

An attacker could record encrypted network traffic or steal encrypted vault files today, then retain them until a future quantum computer can break the classical public-key protection. Long-lived confidential data is most exposed when its encryption keys were exchanged or protected using RSA or elliptic-curve cryptography.

For this vault, stored ciphertext and encrypted file keys are at risk if the file keys are wrapped using RSA or established through a vulnerable classical key exchange. ML-KEM is a post-quantum key-encapsulation mechanism: the recipient uses it to establish shared secret material, then a KDF derives a symmetric key to encrypt (wrap) the file key. ML-KEM does not directly encrypt the file contents or replace AES; AES remains responsible for bulk file encryption. Digital-signature migration is a separate concern because confidentiality and authenticity are different goals.

## Toy RSA exercise

Run the demo with Python 3:

```sh
python3 scripts/toy_rsa.py
```

The public modulus is `n = p * q`. The toy attacker tries candidate divisors until finding `p`, computes `q = n // p`, and then reconstructs the private exponent from the factors. The recovered exponent decrypts the ciphertext. Real RSA uses vastly larger primes, so classical trial division is infeasible at that scale; this toy program is not secure encryption and does not implement production RSA.

## Two-minute explanation

RSA and elliptic-curve cryptography protect public keys by relying on math problems that ordinary computers cannot solve efficiently: factoring for RSA and discrete logarithms for elliptic curves. Shor's algorithm changes that for a sufficiently powerful quantum computer, so merely increasing RSA or ECC key sizes is not a long-term solution. AES and SHA-256 are different: they are symmetric encryption and hashing, and Grover's algorithm only gives an idealized square-root speedup for key search. AES-256 therefore retains about 128 bits of idealized quantum search strength, which is still very strong. The urgent issue is data that must remain secret for years: attackers could save encrypted traffic or vault files now and decrypt them later if RSA or ECC protects their keys. ML-KEM provides a post-quantum way to establish key material; a KDF and AES can then protect the file key and file contents.

## Question I still have

What practical quantum-computer size and error-correction overhead would be needed to run Shor's algorithm against a real-world RSA key?
