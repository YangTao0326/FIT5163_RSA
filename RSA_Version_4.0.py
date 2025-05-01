import math
import random
from Crypto.Util.number import getPrime, inverse

# Generate RSA key pairs, with the first two sharing the same prime factor 'p'
def generate_rsa_key_pairs_with_shared_factor(bits_list):
    key_pairs = []  # List to store generated key pairs
    shared_p = getPrime(bits_list[0] // 2)  # Generate a prime number to be shared
    used_shared_factor = []  # Track whether shared factor was used

    for i, bits in enumerate(bits_list):
        if i < 2:
            p = shared_p  # First two key pairs will share 'p'
            used_shared_factor.append(True)
        else:
            p = getPrime(bits // 2)  # For others, generate a fresh prime
            used_shared_factor.append(False)

        q = getPrime(bits // 2)  # Generate q independently
        N = p * q  # RSA modulus
        phi = (p - 1) * (q - 1)
        e = 65537  # Common public exponent
        d = inverse(e, phi)  # Compute private exponent
        key_pairs.append(((N, e), (N, d)))  # Store public and private key

    return key_pairs, shared_p, used_shared_factor


# Find the greatest common divisor (GCD) of two integers
def custom_find_shared_factor(N1, N2):
    a, b = max(N1, N2), min(N1, N2)
    while b != 0:
        a, b = b, a % b  # Euclidean algorithm
    return a


# Demonstrate detection of shared prime factor between key pairs
def demonstrate_shared_factor(key_pairs, used_shared_factor):
    shared_factors = {}

    for i in range(len(key_pairs)):
        for j in range(i + 1, len(key_pairs)):
            # Only check key pairs that are supposed to share the factor
            if used_shared_factor[i] and used_shared_factor[j]:
                N1 = key_pairs[i][0][0]
                N2 = key_pairs[j][0][0]
                shared_factor = custom_find_shared_factor(N1, N2)
                shared_factors[(i, j)] = shared_factor

    return shared_factors


# Recover private key using known shared prime factor
def recover_private_key(public_key, shared_factor):
    N, e = public_key
    p = shared_factor
    q = N // p  # Recover q from N and known p
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)  # Recompute private key d
    return d


# Encrypt message with RSA public key
def rsa_encrypt(message, public_key):
    N, e = public_key
    return pow(message, e, N)


# Decrypt ciphertext with RSA private key
def rsa_decrypt(ciphertext, private_key, public_key):
    N, _ = public_key
    d = private_key
    return pow(ciphertext, d, N)


# Main driver function to demonstrate shared factor vulnerability
def main():
    bits_list = [1024, 2048, 3072]  # Bit lengths for key generation
    key_pairs, actual_shared_p, used_shared_factor = generate_rsa_key_pairs_with_shared_factor(bits_list)

    print("RSA key pair:")
    for i, (pub, priv) in enumerate(key_pairs):
        print(f"Key pair {i + 1}: Public key N = {pub[0]}, e = {pub[1]}")
        print(f"Key pair {i + 1}: Private key d = {priv[1]}")
        print(f"Key pair {i + 1}: Used shared factor: {used_shared_factor[i]}")

    print("\nHaving shared factor:")
    has_shared = False
    for i in range(len(key_pairs)):
        for j in range(i + 1, len(key_pairs)):
            if used_shared_factor[i] and used_shared_factor[j]:
                print(f"Key pair {i + 1} & Key pair {j + 1} have shared factor")
                has_shared = True
    if not has_shared:
        print("No key pair has shared factor")
    print(f"Actual shared prime factor p = {actual_shared_p}\n")

    shared_factors = demonstrate_shared_factor(key_pairs, used_shared_factor)
    print("Finding shared factor:")
    for (i, j), shared_factor in shared_factors.items():
        print(f"Key pair {i + 1} & Key pair {j + 1} shared factor: {shared_factor}")
        print(f"Correct match: {shared_factor == actual_shared_p}")

    if shared_factors:
        (i, j), shared_factor = next(iter(shared_factors.items()))
        print(f"\nDemonstrate private key recovery and encryption/decryption using Key pair {i + 1}")

        public_key = key_pairs[i][0]
        recovered_d = recover_private_key(public_key, shared_factor)
        print(f"Original private key d: {key_pairs[i][1][1]}")
        print(f"Recovered private key d: {recovered_d}")
        print(f"Correct match: {recovered_d == key_pairs[i][1][1]}\n")

        message = 12345
        print(f"Original message: {message}")
        ciphertext = rsa_encrypt(message, key_pairs[i][0])
        print(f"Ciphertext: {ciphertext}")
        decrypted_message = rsa_decrypt(ciphertext, recovered_d, key_pairs[i][0])
        print(f"Decrypted message: {decrypted_message}")
        print(f"Correct match: {decrypted_message == message}")
    else:
        print("No shared factors found, skipping private key recovery demonstration.")


# Run the program
if __name__ == "__main__":
    main()
