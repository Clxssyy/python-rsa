# Algorithms Project 1 - RSA
# Objective: implement RSA Encryption and apply it to digital signature
import pandas as pd
import numpy as np
import sys
import random
import math
import hashlib


# check if p is prime (most likely a prime)
def FermatPrimalityTest(p, k=5):
    if p <= 1:
        return False
    if p <= 3:
        return True
    for _ in range(k):
        a = random.randint(2, p - 2)
        if pow(a, p - 1, p) != 1:
            return False
    return True


def generate_large_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1
        if FermatPrimalityTest(candidate):
            return candidate


def RSA_key_generation():
    p = generate_large_prime(512)
    q = generate_large_prime(512)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e such that e is relatively prime to (p-1)*(q-1)
    e = random.randint(2, phi - 1)
    while math.gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    # Compute the modular multiplicative inverse of e mod phi
    _, d, _ = extended_gcd(e, phi)
    d = d % phi
    if d < 0:
        d += phi

    pq = pd.Series([p, q])
    en = pd.Series([e, n])
    dn = pd.Series([d, n])
    pq.to_csv("p_q.csv", index=False, header=False)
    en.to_csv("e_n.csv", index=False, header=False)
    dn.to_csv("d_n.csv", index=False, header=False)
    print("done with key generation!")


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def Signing(doc, key):
    with open(doc, 'r') as file:
        content = file.read()
        content = content.strip()

    # Private key
    d, n = int(key[0][0]), int(key[0][1])

    # Generate SHA-256 hash of the file content
    hash_code = hashlib.sha256(content.encode('utf-8')).hexdigest()
    hash_code = int(hash_code, 32)

    # Encrypt the hash code using the private key
    signature = pow(hash_code, d, n)

    # Output the signed content to a file
    with open(doc + '.signed', 'w') as file:
        file.write(content + str(signature))

    print("\nSigned ...")



def verification(doc, key):
    # If the file is not signed, sign it first (not sure if this is the intended behavior or if it should get the signed version of the file)
    if not doc.endswith('.signed'):
        public_key = pd.read_csv("d_n.csv", header=None)
        Signing(doc, public_key)
        doc += '.signed'
        verification(doc, key)
        return

    with open(doc, 'r') as file:
        content = file.read()
        content = content.strip()

    # Public key
    e, n = int(key[0][0]), int(key[0][1])

    # Split the content into the original content and the signature
    signature = content[-308:]
    content = content[:-308]

    # Generate SHA-256 hash of the content
    hash_code = hashlib.sha256(content.encode('utf-8')).hexdigest()

    # Check if the signature is valid
    hash_code = int(hash_code, 32)

    decrypted_hash = pow(int(signature), e, n)

    match = hash_code == decrypted_hash

    # Output the result
    if match:
        print("\nAuthentic!")
    else:
        print("\nModified!")


# No need to change the main function.
def main():
    # part I, command-line arguments will be: python yourProgram.py 1
    if int(sys.argv[1]) == 1:
        RSA_key_generation()
    # part II, command-line will be for example: python yourProgram.py 2 s file.txt
    #                                       or   python yourProgram.py 2 v file.txt.signed
    else:
        (task, fileName) = sys.argv[2:]
        if "s" in task:  # do signing
            doc = fileName
            key = pd.read_csv("d_n.csv", header=None)
            Signing(fileName, key)
        else:
            # do verification
            doc = fileName
            key = pd.read_csv("e_n.csv", header=None)
            verification(fileName, key)

    print("done!")


if __name__ == '__main__':
    main()