from utils import pkcs7_pad, pkcs7_unpad

BLOCK_SIZE = 8   
KEY_SIZE   = 16  
ROUNDS     = 25

SBOX     = [0x6, 0x5, 0xC, 0xA, 0x1, 0xE, 0x7, 0x9,
            0xB, 0x0, 0x3, 0xD, 0x8, 0xF, 0x4, 0x2]
SBOX_INV = [SBOX.index(i) for i in range(16)]

def _to_state(block):
    return [int.from_bytes(block[i*2:(i+1)*2], 'little') for i in range(4)]

def _from_state(state):
    return b''.join(w.to_bytes(2, 'little') for w in state)

def _sub_nibbles(state, sbox):
    return [sum(sbox[(row >> (4*i)) & 0xF] << (4*i) for i in range(4))
            for row in state]

SHIFTS = [0, 1, 12, 13]

def _shift_rows(state):
    return [(row << s | row >> (16 - s)) & 0xFFFF
            for row, s in zip(state, SHIFTS)]

def _shift_rows_inv(state):
    return [(row >> s | row << (16 - s)) & 0xFFFF
            for row, s in zip(state, SHIFTS)]

def _add_round_key(state, rk):
    return [s ^ k for s, k in zip(state, rk)]

def _key_schedule(key):
    # 8 words de 16 bits
    w = [int.from_bytes(key[i*2:(i+1)*2], 'little') for i in range(8)]

    # Constantes de ronda (RC) — fixas no RECTANGLE
    RC = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
          0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6,
          0x97, 0x35, 0x6A, 0xD4, 0xB3]

    round_keys = []
    for r in range(ROUNDS):

        round_keys.append(w[:4])

        w[:4] = _sub_nibbles(w[:4], SBOX)

        w[0] ^= RC[r]

        w = w[1:] + [w[0]]

    round_keys.append(w[:4])
    return round_keys

def _encrypt_block(key, block):
    state = _to_state(block)
    rks = _key_schedule(key)
    for r in range(ROUNDS):
        state = _add_round_key(state, rks[r])
        state = _sub_nibbles(state, SBOX)
        state = _shift_rows(state)
    state = _add_round_key(state, rks[ROUNDS])
    return _from_state(state)

def _decrypt_block(key, block):
    state = _to_state(block)
    rks = _key_schedule(key)
    state = _add_round_key(state, rks[ROUNDS])
    for r in range(ROUNDS - 1, -1, -1):
        state = _shift_rows_inv(state)
        state = _sub_nibbles(state, SBOX_INV)
        state = _add_round_key(state, rks[r])
    return _from_state(state)

def encrypt(key, data):
    data = pkcs7_pad(data, BLOCK_SIZE)
    return b''.join(_encrypt_block(key, data[i:i+BLOCK_SIZE])
                    for i in range(0, len(data), BLOCK_SIZE))

def decrypt(key, data):
    result = b''.join(_decrypt_block(key, data[i:i+BLOCK_SIZE])
                      for i in range(0, len(data), BLOCK_SIZE))
    return pkcs7_unpad(result)
