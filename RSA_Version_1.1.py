import math
import random
from Crypto.Util.number import getPrime, GCD, inverse


#step a
def generate_rsa_key_pairs_with_shared_factor(bits_list):
    key_pairs = []

    shared_p = getPrime(bits_list[0] // 2)
    for bits in bits_list:
        q = getPrime(bits // 2)
        N = shared_p * q
        phi = (shared_p - 1) * (q - 1)
        e = 65537
        d = inverse(e, phi)
        key_pairs.append(((N, e), (N, d)))

    return key_pairs, shared_p


# step b:
def find_shared_factor(N1, N2):
    return math.gcd(N1, N2)


# step c:
def demonstrate_shared_factor(key_pairs):

    N1 = key_pairs[0][0][0]
    N2 = key_pairs[1][0][0]
    shared_factor = find_shared_factor(N1, N2)
    return shared_factor


# step d:
def recover_private_key(public_key, shared_factor):
    N, e = public_key
    p = shared_factor
    q = N // p
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return d


# step e:
def rsa_encrypt(message, public_key):
    N, e = public_key
    # encrypt: c = m^e mod N
    return pow(message, e, N)


def rsa_decrypt(ciphertext, private_key, public_key):
    N, _ = public_key
    d = private_key
    # decrypt: m = c^d mod N
    return pow(ciphertext, d, N)


# main function
def main():
    # step a:
    bits_list = [1024, 2048, 3072]
    key_pairs, actual_shared_p = generate_rsa_key_pairs_with_shared_factor(bits_list)
    print("RSA key pair:")
    for i, (pub, priv) in enumerate(key_pairs):
        print(f"Key pair {i + 1}: Public key N = {pub[0]}, e = {pub[1]}")
        print(f"Key pair {i + 1}: Private key d = {priv[1]}")
    print(f"Actual sharing factor p = {actual_shared_p}\n")

    # step b 和 c:
    shared_factor = demonstrate_shared_factor(key_pairs)
    print(f"Sharing factor: {shared_factor}")

    # step d:
    public_key = key_pairs[0][0]
    recovered_d = recover_private_key(public_key, shared_factor)
    print(f"Original private key d: {key_pairs[0][1][1]}")
    print(f"Recovered private key d: {recovered_d}")
    print(f"Accuracy: {recovered_d == key_pairs[0][1][1]}\n")

    # step e:
    message = 12345
    print(f"Original text: {message}")
    # Use the first key
    ciphertext = rsa_encrypt(message, key_pairs[0][0])
    print(f"ciphertext: {ciphertext}")

    decrypted_message = rsa_decrypt(ciphertext, recovered_d, key_pairs[0][0])
    print(f"decrypted_message: {decrypted_message}")
    print(f"Accuracy: {decrypted_message == message}")


# 运行程序
if __name__ == "__main__":
    main()