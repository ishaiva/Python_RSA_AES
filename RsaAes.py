import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding

def hash_key(key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(bytes(key, 'utf-8'))
    return key

def generate_aes_key():
    while True:
        key = input("Enter a key (must be at least 10 characters and include letters and numbers): ")
        if len(key) < 10:
            print("Key must be at least 10 characters long.")
        elif not any(char.isalpha() for char in key) or not any(char.isdigit() for char in key):
            print("Key must contain both letters and numbers.")
        else:
            return key

def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_key_to_file(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

def encrypt_file_aes(file_path, key):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    salt = os.urandom(16)
    salted_key = hash_key(key, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(salted_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    encrypted_file_path = file_path + '.encrypted_aes'
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

    print("File encrypted with AES successfully.")

def decrypt_file_aes(file_path, key):
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_data = encrypted_data[32:]

    salted_key = hash_key(key, salt)

    cipher = Cipher(algorithms.AES(salted_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    decrypted_file_path = os.path.splitext(file_path)[0]
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    print("File decrypted with AES successfully.")

def encrypt_rsa_file(file_path, public_key_path, output_path):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    public_key = RSA.import_key(open(public_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(file_data)

    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

    print("File encrypted with RSA successfully.")

def decrypt_rsa_file(file_path, private_key_path, output_path):
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    private_key = RSA.import_key(open(private_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)

    with open(output_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    print("File decrypted with RSA successfully.")

def main():
    print("Hello, this is a code that uses Python to encrypt and decrypt files. proceed with caution! ")

    while True:
        print("Choose an option:")
        print("1. Encrypt a file with AES")
        print("2. Decrypt a file with AES")
        print("3. Generate RSA key pair")
        print("4. Encrypt a file with RSA")
        print("5. Decrypt a file with RSA")
        print("6. Quit")

        choice = input("Enter the number of your choice (1, 2, 3, 4, 5, or 6): ")

        if choice == "1":
            file_path = input("Enter the path of the file to encrypt with AES: ")
            key = generate_aes_key()
            encrypt_file_aes(file_path, key)

        elif choice == "2":
            file_path = input("Enter the path of the file to decrypt with AES: ")
            key = generate_aes_key()
            decrypt_file_aes(file_path, key)

        elif choice == "3":
            private_key, public_key = generate_rsa_key_pair()
            save_key_to_file(private_key, 'private_key.pem')
            save_key_to_file(public_key, 'public_key.pem')
            print("RSA key pair generated and saved successfully.")

        elif choice == "4":
            file_path = input("Enter the path of the file to encrypt with RSA: ")
            public_key_path = input("Enter the path to the recipient's public key: ")
            output_path = input("Enter the path for the encrypted output file: ")
            encrypt_rsa_file(file_path, public_key_path, output_path)

        elif choice == "5":
            file_path = input("Enter the path of the file to decrypt with RSA: ")
            private_key_path = input("Enter the path to your private key: ")
            output_path = input("Enter the path for the decrypted output file: ")
            decrypt_rsa_file(file_path, private_key_path, output_path)

        elif choice == "6":
            print("Program terminated.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
