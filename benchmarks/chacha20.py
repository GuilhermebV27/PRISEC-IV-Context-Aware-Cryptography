from Crypto.Cipher import ChaCha20_Poly1305
import os

NONCE_SIZE = 12  # bytes (96 bits) — padrão RFC 8439
TAG_SIZE   = 16  # bytes (authentication tag)

def encrypt(key: bytes, data: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ciphertext

def decrypt(key: bytes, data: bytes) -> bytes:
    nonce      = data[:NONCE_SIZE]
    tag        = data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = data[NONCE_SIZE + TAG_SIZE:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)