# Secure File Locker
# Coded by Pakistani Ethical Hacker Mr. Sabaz Ali Khan
# This script provides a simple way to encrypt and decrypt files using a password.
# It uses the cryptography library for secure encryption.
# Install required package: pip install cryptography

import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import getpass

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a symmetric key from the password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Increase for more security
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(file_path: str, password: str):
    """Encrypt the file with the given password."""
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password, salt)
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as file:
        data = file.read()
    
    encrypted_data = fernet.encrypt(data)
    
    # Write salt + encrypted data to a new file
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as file:
        file.write(salt + encrypted_data)
    
    print(f"File encrypted successfully: {encrypted_file_path}")
    # Optionally, delete the original file for security
    # os.remove(file_path)

def decrypt_file(encrypted_file_path: str, password: str):
    """Decrypt the file with the given password."""
    with open(encrypted_file_path, 'rb') as file:
        salt = file.read(16)  # Read the salt
        encrypted_data = file.read()
    
    key = derive_key(password, salt)
    fernet = Fernet(key)
    
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        decrypted_file_path = encrypted_file_path.replace('.enc', '')
        
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)
        
        print(f"File decrypted successfully: {decrypted_file_path}")
    except Exception as e:
        print("Decryption failed. Incorrect password or corrupted file.")

def main():
    print("Secure File Locker - Coded by Mr. Sabaz Ali Khan")
    choice = input("Enter 'e' to encrypt or 'd' to decrypt: ").lower()
    file_path = input("Enter the file path: ")
    password = getpass.getpass("Enter the password: ")
    
    if choice == 'e':
        encrypt_file(file_path, password)
    elif choice == 'd':
        decrypt_file(file_path, password)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()