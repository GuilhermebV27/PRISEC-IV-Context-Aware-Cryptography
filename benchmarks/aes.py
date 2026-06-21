from Crypto.Cipher import AES

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def decrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]