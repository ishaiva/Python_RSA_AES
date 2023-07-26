from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

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

def encrypt_file(file_path, public_key_path, output_path):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    public_key = RSA.import_key(open(public_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(file_data)

    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(encrypted_file_path, private_key_path, output_path):
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    private_key = RSA.import_key(open(private_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)

    with open(output_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

def main():
    print("""
 _______     ______        _                          
|_   __ \  .' ____ \      / \                         
  | |__) | | (___ \_|    / _ \       _ .--.   _   __  
  |  __ /   _.____`.    / ___ \     [ '/'`\ \[ \ [  ] 
 _| |  \ \_| \____) | _/ /   \ \_  _ | \__/ | \ '/ /  
|____| |___|\______.'|____| |____|(_)| ;.__/[\_:  /   
                                    [__|     \__.'    
""")
    print("Welcome to the RSA file encryption/decryption program!")

    while True:
        print("1. Generate RSA Key Pair")
        print("2. Encrypt a file")
        print("3. Decrypt a file")
        print("4. Quit")

        choice = input("Enter your choice (1, 2, 3, or 4): ")

        if choice == "1":
            private_key, public_key = generate_rsa_key_pair()
            save_key_to_file(private_key, 'private_key.pem')
            save_key_to_file(public_key, 'public_key.pem')
            print("RSA key pair generated and saved to 'private_key.pem' and 'public_key.pem'.")

        elif choice == "2":
            file_path = input("Enter the path of the file to encrypt: ")
            public_key_path = input("Enter the path to the recipient's public key: ")
            output_path = input("Enter the path for the encrypted output file: ")

            encrypt_file(file_path, public_key_path, output_path)
            print("[+] File encrypted successfully.")

        elif choice == "3":
            encrypted_file_path = input("Enter the path of the file to decrypt: ")
            private_key_path = input("Enter the path to your private key: ")
            output_path = input("Enter the path for the decrypted output file: ")

            decrypt_file(encrypted_file_path, private_key_path, output_path)
            print("[+] File decrypted successfully.")

        elif choice == "4":
            print("[=]Program terminated.")
            break

        else:
            print("[-] Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
