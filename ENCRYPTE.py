import os
import base64
import hashlib
from cryptography.fernet import Fernet

def hash_key(key):

    salt = b'salt_' 
    key = bytes(key, 'utf-8')
    hashed_key = hashlib.pbkdf2_hmac('sha256', key, salt, 100000)
    return base64.urlsafe_b64encode(hashed_key)

def get_key():
   
    while True:
        key = input("Enter a key (must be at least 10 characters and include letters and numbers): ")
        if len(key) < 10:
            print("[-] Key must be at least 10 characters long.")
        elif not any(char.isalpha() for char in key) or not any(char.isdigit() for char in key):
            print("[-] Key must contain both letters and numbers.")
        else:
            return key

def encrypt_file(file_path, key):
    
    with open(file_path, 'rb') as file:
        file_data = file.read()
    fernet_key = Fernet(hash_key(key))
    encrypted_data = fernet_key.encrypt(file_data)
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    print(f"[+] File {file_path} encrypted successfully.\n[+] Encrypted file: {encrypted_file_path}")

def decrypt_file(file_path, key):
    
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    fernet_key = Fernet(hash_key(key))
    decrypted_data = fernet_key.decrypt(encrypted_data)
    decrypted_file_path = os.path.splitext(file_path)[0]
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
    print(f"[+] File {file_path} decrypted successfully.\n[+] Decrypted file: {decrypted_file_path}")

def main():
   
    while True:
        print("""
          )         (        )  (
      ( /(    (    )\ )  ( /(  )\ )  *   )
 (    )\())   )\  (()/(  )\())(()/(` )  /( (              (
 )\  ((_)\  (((_)  /(_))((_)\  /(_))( )(_)))\      `  )   )\ )
((_)  _((_) )\___ (_)) __ ((_)(_)) (_(_())((_)     /(/(  (()/(
| __|| \| |((/ __|| _ \\ \ / /| _ \|_   _|| __|   ((_)_\  )(_))
| _| | .` | | (__ |   / \ V / |  _/  | |  | _|  _ | '_ \)| || |
|___||_|\_|  \___||_|_\  |_|  |_|    |_|  |___|(_)| .__/  \_, |
                                                  |_|     |__/
""")
        choice = input("Enter 'e' to encrypt a file, 'd' to decrypt a file, or 'q' to quit: ")
        if choice.lower() == 'q':
            break
        elif choice.lower() == 'e':
            file_path = input("Enter the file path to encrypt: ")
            while not os.path.isfile(file_path):
                file_path = input("[-] Invalid file path. Enter the file path to encrypt: ")
            key = get_key()
            encrypt_file(file_path, key)
        elif choice.lower() == 'd':
            file_path = input("Enter the file path to decrypt: ")
            while not os.path.isfile(file_path):
                file_path = input("[-] Invalid file path. Enter the file path to decrypt: ")
            key = input("Enter the key to decrypt the file: ")
            decrypt_file(file_path, key)
        else:
            print("[-] Invalid choice. Please enter 'e', 'd', or 'q'.")

if __name__ == '__main__':
    main()

