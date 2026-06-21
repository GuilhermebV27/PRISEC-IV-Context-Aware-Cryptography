from Crypto.Cipher import ChaCha20


def encrypt(key, data):
    cipher = ChaCha20.new(key=key)
    return cipher.nonce + cipher.encrypt(data)


def decrypt(key, data):
    nonce = data[:8]
    ciphertext = data[8:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)