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

