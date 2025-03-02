# Cryptography
Encryption &amp; Decryption Algorithm implemented in Python

The python script encrypts or decrypts a file using a password. It uses the password-key derivation function to derive a 32-byte key from a password passed as an arguement and a random 16 byte salt. The script ensures the unicity of the key each time the script is used by storing the salt at the beginning of the encrypted file. It uses AES-128-CBC via Fernet with the derived key to create the encrypted file that is then saved with the extension .enc in the same directory containing both salt and ciphertext in binary format.

When decryption is called by passing the additional "-d" in the command line the script extracts the salt and regenerates the the key from the password. Uses Fernet to decrypt the file and saves it in the same directory under the name "decrypted.txt"

The script handles FileNotFound, InvalidToken (wrong password) errors.

It is operable from the Unix terminal using "python3 script.py filename.txt password" for encryption and "python3 script.py password -d filename.txt.enc" for decryption.
