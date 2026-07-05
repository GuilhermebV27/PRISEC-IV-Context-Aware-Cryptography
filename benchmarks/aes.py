from Crypto.Cipher import AES
import os

NONCE_SIZE = 8
TAG_SIZE = 16  

def encrypt(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CCM, nonce=os.urandom(NONCE_SIZE), mac_len=TAG_SIZE)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext


def decrypt(key: bytes, data: bytes) -> bytes:
    nonce = data[:NONCE_SIZE]
    tag = data[NONCE_SIZE : NONCE_SIZE + TAG_SIZE]
    ciphertext = data[NONCE_SIZE + TAG_SIZE :]
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=TAG_SIZE)
    return cipher.decrypt_and_verify(ciphertext, tag)
