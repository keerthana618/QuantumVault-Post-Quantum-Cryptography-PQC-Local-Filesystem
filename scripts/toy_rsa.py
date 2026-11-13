"""Break a deliberately tiny RSA example by trial-dividing its public modulus."""

from math import gcd, isqrt


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    divisor, x, y = extended_gcd(b, a % b)
    return divisor, y, x - (a // b) * y


def mod_inverse(value: int, modulus: int) -> int:
    divisor, coefficient, _ = extended_gcd(value, modulus)
    if divisor != 1:
        raise ValueError("The value has no modular inverse.")
    return coefficient % modulus


def next_prime(candidate: int) -> int:
    def is_prime(value: int) -> bool:
        if value < 2:
            return False
        return all(value % divisor for divisor in range(2, isqrt(value) + 1))

    while not is_prime(candidate):
        candidate += 1
    return candidate


def factor_toy_modulus(modulus: int) -> tuple[int, int]:
    for candidate in range(2, isqrt(modulus) + 1):
        if modulus % candidate == 0:
            return candidate, modulus // candidate
    raise ValueError("The modulus was not composite.")


def main() -> None:
    p, q = next_prime(10_007), next_prime(20_011)
    modulus = p * q
    phi = (p - 1) * (q - 1)
    public_exponent = 65_537
    if gcd(public_exponent, phi) != 1:
        raise ValueError("Choose primes for which the public exponent is invertible.")
    private_exponent = mod_inverse(public_exponent, phi)

    message = 123_456
    ciphertext = pow(message, public_exponent, modulus)
    print("public key (n, e):", modulus, public_exponent)
    print("ciphertext:", ciphertext)

    # The attacker needs only the public modulus to recover these toy factors.
    recovered_p, recovered_q = factor_toy_modulus(modulus)
    recovered_phi = (recovered_p - 1) * (recovered_q - 1)
    recovered_private_exponent = mod_inverse(public_exponent, recovered_phi)
    recovered_message = pow(ciphertext, recovered_private_exponent, modulus)
    print("attacker factored n:", recovered_p, "*", recovered_q)
    print("attacker recovered message:", recovered_message)
    assert recovered_message == message


if __name__ == "__main__":
    main()
