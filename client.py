from cryptography.hazmat.primitives.asymmetric import ec, padding,ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from os import urandom
import base64

from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

import base64


priv_key = ed25519.Ed25519PrivateKey.generate()
pub_key = priv_key.public_key()


with open("client_private.pem", "wb") as f:
    f.write(
        priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

with open("client_public.pem", "wb") as f:
    f.write(
        pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

def aes_encrypt(message: bytes, key: bytes):
    iv = urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode()


aes_key = urandom(32)

plaintext = b"Halo ini merupakan pesan untuk testing"
encrypted_message = aes_encrypt(plaintext, aes_key)

signature = priv_key.sign(encrypted_message.encode())

print("Message:", plaintext.decode())
print("Encrypted Message:", encrypted_message)
print("Signature:", base64.b64encode(signature).decode())
print("AES Key:", base64.b64encode(aes_key).decode())
