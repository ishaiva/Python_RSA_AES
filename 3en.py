import os
import base64
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

def get_key():
    while True:
        key = input("Enter a key (must be at least 10 characters and include letters and numbers): ")
        if key.lower() == 'q':
            exit_program()
        elif len(key) < 10:
            print("Key must be at least 10 characters long.")
        elif not any(char.isalpha() for char in key) or not any(char.isdigit() for char in key):
            print("Key must contain both letters and numbers.")
        else:
            return key

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        file_data = file.read()

    salt = os.urandom(16)
    salted_key = hash_key(key, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(salted_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(salt + iv + encrypted_data)

    print("File encrypted successfully.")

def decrypt_file(file_path, key):
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
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    print("File decrypted successfully.")

def exit_program():
    print("Program terminated.")
    exit()

def main():
    print("""  ____                           
 |___ \                          
   __) | ___ _ __    _ __  _   _ 
  |__ < / _ \ '_ \  | '_ \| | | |
  ___) |  __/ | | |_| |_) | |_| |
 |____/ \___|_| |_(_) .__/ \__, |
                    | |     __/ |
                    |_|    |___/ """)
    print("Welcome to the encryption/decryption program!")
    print("Enter 'q' at any stage to quit the program.")

    while True:
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Quit")

        choice = input("Enter your choice (1, 2, or 3): ")

        if choice.lower() == 'q':
            exit_program()
        elif choice == "1":
            file_path = input("Enter the path of the file to encrypt: ")

            if file_path.lower() == 'q':
                exit_program()

            key = get_key()
            encrypt_file(file_path, key)

        elif choice == "2":
            file_path = input("Enter the path of the file to decrypt: ")

            if file_path.lower() == 'q':
                exit_program()

            key = get_key()
            decrypt_file(file_path, key)

        elif choice == "3":
            exit_program()
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
