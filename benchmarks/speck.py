from utils import pkcs7_pad, pkcs7_unpad

MASK = 0xFFFFFFFFFFFFFFFF  # 64 bits
BLOCK_SIZE = 16  # bytes (128 bits)


def _rotr(x, n): return ((x >> n) | (x << (64 - n))) & MASK
def _rotl(x, n): return ((x << n) | (x >> (64 - n))) & MASK


def _key_schedule(key):
    k = [int.from_bytes(key[i*8:(i+1)*8], 'little') for i in range(2)]
    round_keys = [k[0]]
    for i in range(31):
        k[1] = (_rotr(k[1], 8) + round_keys[i]) & MASK
        k[1] ^= i
        round_keys.append((_rotl(round_keys[i], 3) ^ k[1]))
        k = k[1:] + [k[0]]
    return round_keys


def _encrypt_block(key, block):
    round_keys = _key_schedule(key)
    x = int.from_bytes(block[8:16], 'little')
    y = int.from_bytes(block[0:8], 'little')
    for k in round_keys:
        x = (_rotr(x, 8) + y) & MASK
        x ^= k
        y = _rotl(y, 3) ^ x
    return y.to_bytes(8, 'little') + x.to_bytes(8, 'little')


def _decrypt_block(key, block):
    round_keys = _key_schedule(key)
    x = int.from_bytes(block[8:16], 'little')
    y = int.from_bytes(block[0:8], 'little')
    for k in reversed(round_keys):
        y = _rotr(y ^ x, 3)
        x = _rotl((x ^ k) - y & MASK, 8)
    return y.to_bytes(8, 'little') + x.to_bytes(8, 'little')


def encrypt(key, data):
    data = pkcs7_pad(data, BLOCK_SIZE)
    return b''.join(_encrypt_block(key, data[i:i+BLOCK_SIZE])
                    for i in range(0, len(data), BLOCK_SIZE))


def decrypt(key, data):
    result = b''.join(_decrypt_block(key, data[i:i+BLOCK_SIZE])
                      for i in range(0, len(data), BLOCK_SIZE))
    return pkcs7_unpad(result)
