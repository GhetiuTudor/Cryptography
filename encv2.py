import sys
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken


def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt(filename, password):
    try:
        salt = os.urandom(16)  
        key = generate_key(password, salt)  
        cipher = Fernet(key)

        with open(filename, "rb") as file:
            plaintext = file.read()

        ciphertext = cipher.encrypt(plaintext)
        output_file = filename + ".enc"

        with open(output_file, "wb") as enc_file:
            enc_file.write(salt + ciphertext)  

        print(f" Encrypted: {output_file}")
    except FileNotFoundError:
        print(" Error: File not found.")
    except Exception as e:
        print(f" Encryption failed: {e}")


def decrypt(enc_filename, password):
    try:
        with open(enc_filename, "rb") as enc_file:
            salt = enc_file.read(16)  
            ciphertext = enc_file.read()

        key = generate_key(password, salt)  
        cipher = Fernet(key)

        plaintext = cipher.decrypt(ciphertext)
        output_file = "decrypted.txt"

        with open(output_file, "wb") as dec_file:
            dec_file.write(plaintext)

        print(f"Decrypted: {output_file}")
    except FileNotFoundError:
        print(" Error: Encrypted file not found.")
    except InvalidToken:
        print(" Error: Incorrect password or corrupted file.")
    except Exception as e:
        print(f" Decryption failed: {e}")


def main():
    args = sys.argv[1:]

    if len(args) == 2:  
        encrypt(args[0], args[1])
    elif len(args) == 3 and args[1] == "-d":  
        decrypt(args[2], args[0])
    else:
        print("Usage:")
        print("  Encrypt: python script.py filename password")
        print("  Decrypt: python script.py password -d encrypted_file.enc")

if __name__ == "__main__":
    main()