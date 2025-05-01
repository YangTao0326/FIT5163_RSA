import math
import random
from Crypto.Util.number import getPrime, inverse

# Generate RSA key pairs
def generate_rsa_key_pairs_with_shared_factor(bits_list):
    key_pairs = []
    shared_p = getPrime(bits_list[0] // 2)
    used_shared_factor = []

    for i, bits in enumerate(bits_list):
        if i < 2:
            p = shared_p
            used_shared_factor.append(True)
        else:
            p = getPrime(bits // 2)
            used_shared_factor.append(False)

        q = getPrime(bits // 2)
        N = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = inverse(e, phi)
        key_pairs.append(((N, e), (N, d)))

    return key_pairs, shared_p, used_shared_factor


# Find the greatest common divisor (GCD) of two integers
def custom_find_shared_factor(N1, N2):
    a, b = max(N1, N2), min(N1, N2)
    while b != 0:
        a, b = b, a % b
    return a
# Demonstrate detection of shared prime factor between key pairs
def demonstrate_shared_factor(key_pairs, used_shared_factor):
    shared_factors = {}

    for i in range(len(key_pairs)):
        for j in range(i + 1, len(key_pairs)):
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
    q = N // p
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return d


# Encrypt message with RSA public key
def rsa_encrypt(message, public_key):
    N, e = public_key
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
        message_int = int.from_bytes(message_bytes, 'big')
        if message_int >= N:
            raise ValueError("Message too large for RSA modulus N")
    else:
        message_int = message
    return pow(message_int, e, N)
# Decrypt ciphertext with RSA private key
def rsa_decrypt(ciphertext, private_key, public_key):
    N, _ = public_key
    d = private_key
    decrypted_int = pow(ciphertext, d, N)
    try:
        byte_length = (decrypted_int.bit_length() + 7) // 8
        decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')
        return decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return decrypted_int


# Main driver function
def main():
    bits_list = [1024, 2048, 3072]
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

        message = "Let's learn RSA!"
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
