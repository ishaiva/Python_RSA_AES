# File Encryption and Decryption with RSA and AES in Python

![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)

This Python script allows you to encrypt and decrypt files using both RSA and AES encryption algorithms. It provides a command-line interface for ease of use.

## Table of Contents

- [Introduction](#introduction)
- [How RSA Encryption Works](#how-rsa-encryption-works)
- [How AES Encryption Works](#how-aes-encryption-works)
- [Script Overview](#script-overview)
- [Usage](#usage)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)

## Introduction

File encryption is essential for safeguarding sensitive data from unauthorized access. This script utilizes two powerful encryption algorithms: RSA and AES.

- **RSA (Rivest–Shamir–Adleman)**: It is an asymmetric encryption algorithm, meaning it uses a pair of keys - a public key for encryption and a private key for decryption. The public key can be safely shared, while the private key must be kept secret.

- **AES (Advanced Encryption Standard)**: It is a symmetric encryption algorithm, which means it uses the same key for both encryption and decryption. The AES algorithm is widely used due to its efficiency and security.

## How RSA Encryption Works

RSA encryption is based on the mathematical properties of large prime numbers. It involves the following steps:

1. Key Generation: Generate two large prime numbers, `p` and `q`. Calculate their product `n = p * q`, and find the totient `φ(n) = (p - 1) * (q - 1)`.
2. Choose an integer `e` such that `1 < e < φ(n)`, and `e` is coprime to `φ(n)` (i.e., their greatest common divisor is 1). `e` becomes the public key exponent.
3. Compute the modular multiplicative inverse `d` of `e` modulo `φ(n)` (i.e., `(e * d) % φ(n) = 1`). `d` becomes the private key exponent.
4. The public key is `(e, n)`, and the private key is `(d, n)`.

To encrypt a message `m`, it is raised to the power of `e` modulo `n`:

c = m^e % n

To decrypt the ciphertext `c`, it is raised to the power of `d` modulo `n`:

m = c^d % n


## How AES Encryption Works

AES encryption is a symmetric block cipher, meaning it encrypts data in fixed-size blocks. It involves the following steps:

1. Key Expansion: The original AES key is expanded into multiple round keys using a key schedule algorithm.
2. Initial Round: AddRoundKey operation - XOR the input block with the first round key.
3. Main Rounds: A series of transformations (SubBytes, ShiftRows, MixColumns, AddRoundKey) are applied in multiple rounds (10, 12, or 14 rounds based on key size).
4. Final Round: The same transformations are applied, except MixColumns, and the last round key is XORed with the output.
5. The encrypted data is the output of the final round.

## Script Overview

The Python script `file_encrypt_decrypt.py` provides functions to perform both RSA and AES encryption and decryption. Here's an overview of the script:

- `hash_key(key, salt)`: This function hashes the input `key` using PBKDF2HMAC to derive a consistent key for AES encryption.

- `generate_aes_key()`: This function prompts the user to enter a passphrase for AES encryption and ensures its validity.

- `generate_rsa_key_pair()`: This function generates an RSA key pair with a key size of 2048 bits.

- `save_key_to_file(key, filename)`: This function saves a key to a file.

- `load_key_from_file(filename)`: This function loads a key from a file.

- `encrypt_file_aes(file_path, key)`: This function encrypts a file using AES encryption.

- `decrypt_file_aes(file_path, key)`: This function decrypts an AES-encrypted file.

- `encrypt_rsa_file(file_path, public_key_path, output_path)`: This function encrypts a file using RSA encryption.

- `decrypt_rsa_file(file_path, private_key_path, output_path)`: This function decrypts an RSA-encrypted file.

## Usage

1. Clone the repository to your local machine.

2. Install the required dependencies by running:

pip install cryptography pycryptodome


3. Run the script:

python file_encrypt_decrypt.py


4. Choose the desired encryption/decryption option from the command-line menu.

## Dependencies

The script requires the following Python libraries:

- `cryptography`: For RSA encryption and decryption.
- `pycryptodome`: For AES encryption and decryption.

You can install these libraries using `pip`:

pip install cryptography pycryptodome


## Contributing

Contributions to this project are welcome! If you find any issues or have suggestions for improvements, please feel free to create an issue or submit a pull request.

## License

MIT License

Copyright (c) [2023] [ishaiva]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

