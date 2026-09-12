from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import struct

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def encrypt(key, plaintext):
    key_bytes = struct.pack('>I', key)
    key_bytes = key_bytes.ljust(16, b'\0')
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = pad(plaintext).encode()
    encrypted = encryptor.update(padded_plaintext) + encryptor.finalize()
    return encrypted

if __name__ == "__main__":
    key = 1
    msg = "123"
    print(encrypt(key,msg))