import numpy as np
from numba import njit, uint16, uint32, uint8
from utils import pkcs7_pad, pkcs7_unpad

BLOCK_SIZE = 8
KEY_SIZE   = 16
ROUNDS     = 25

SBOX     = np.array([0x6,0x5,0xC,0xA,0x1,0xE,0x7,0x9,
                     0xB,0x0,0x3,0xD,0x8,0xF,0x4,0x2], dtype=np.uint16)
SBOX_INV = np.array([SBOX.tolist().index(i) for i in range(16)], dtype=np.uint16)

RC = np.array([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,
               0x6C,0xD8,0xAB,0x4D,0x9A,0x2F,0x5E,0xBC,0x63,0xC6,
               0x97,0x35,0x6A,0xD4,0xB3], dtype=np.uint32)

SHIFT_AMOUNTS = np.array([0, 1, 12, 13], dtype=np.uint16)


@njit(cache=True)
def _sub_nibbles_16(row, sbox):
    """Aplica S-box aos 4 nibbles de uma word de 16 bits."""
    out = uint16(0)
    for i in range(4):
        nibble = (row >> uint16(4 * i)) & uint16(0xF)
        out |= uint16(sbox[nibble]) << uint16(4 * i)
    return out


@njit(cache=True)
def _sub_nibbles_32_low8(row, sbox):
    """Aplica S-box apenas aos 8 nibbles inferiores de uma word de 32 bits."""
    out = row & uint32(0xFFFFFFFF)
    for i in range(8):
        nibble = (row >> uint32(4 * i)) & uint32(0xF)
        out = (out & ~(uint32(0xF) << uint32(4 * i))) | (uint32(sbox[nibble]) << uint32(4 * i))
    return out


@njit(cache=True)
def _key_schedule_jit(k0, k1, k2, k3):
    """
    RECTANGLE-128 key schedule.
    Input: 4 words de 32 bits (rows do registo de chave).
    Output: 26 subchaves de 4×16 bits.
    """
    MASK32 = uint32(0xFFFFFFFF)
    rks = np.empty((26, 4), dtype=np.uint16)

    r0, r1, r2, r3 = uint32(k0), uint32(k1), uint32(k2), uint32(k3)

    for i in range(ROUNDS):
        rks[i, 0] = uint16(r0 & uint32(0xFFFF))
        rks[i, 1] = uint16(r1 & uint32(0xFFFF))
        rks[i, 2] = uint16(r2 & uint32(0xFFFF))
        rks[i, 3] = uint16(r3 & uint32(0xFFFF))

        r0 = _sub_nibbles_32_low8(r0, SBOX)
        r1 = _sub_nibbles_32_low8(r1, SBOX)
        r2 = _sub_nibbles_32_low8(r2, SBOX)
        r3 = _sub_nibbles_32_low8(r3, SBOX)

        new_r0 = (((r0 << uint32(8)) | (r0 >> uint32(24))) & MASK32) ^ r1
        new_r1 = r2
        new_r2 = (((r2 << uint32(16)) | (r2 >> uint32(16))) & MASK32) ^ r3
        new_r3 = r0
        r0, r1, r2, r3 = new_r0, new_r1, new_r2, new_r3

        r0 ^= uint32(RC[i]) & uint32(0x1F)

    rks[ROUNDS, 0] = uint16(r0 & uint32(0xFFFF))
    rks[ROUNDS, 1] = uint16(r1 & uint32(0xFFFF))
    rks[ROUNDS, 2] = uint16(r2 & uint32(0xFFFF))
    rks[ROUNDS, 3] = uint16(r3 & uint32(0xFFFF))

    return rks


@njit(cache=True)
def _encrypt_bulk(k0, k1, k2, k3, blocks):
    """
    blocks: (N, 4) uint16 — 4 rows de 16 bits por bloco
    """
    out = np.empty_like(blocks)
    rks = _key_schedule_jit(k0, k1, k2, k3)

    for i in range(blocks.shape[0]):
        s0 = blocks[i, 0]
        s1 = blocks[i, 1]
        s2 = blocks[i, 2]
        s3 = blocks[i, 3]

        for r in range(ROUNDS):
            s0 ^= rks[r, 0]
            s1 ^= rks[r, 1]
            s2 ^= rks[r, 2]
            s3 ^= rks[r, 3]

            s0 = _sub_nibbles_16(s0, SBOX)
            s1 = _sub_nibbles_16(s1, SBOX)
            s2 = _sub_nibbles_16(s2, SBOX)
            s3 = _sub_nibbles_16(s3, SBOX)

            s1 = uint16((s1 << uint16(1))  | (s1 >> uint16(15)))
            s2 = uint16((s2 << uint16(12)) | (s2 >> uint16(4)))
            s3 = uint16((s3 << uint16(13)) | (s3 >> uint16(3)))

        s0 ^= rks[ROUNDS, 0]
        s1 ^= rks[ROUNDS, 1]
        s2 ^= rks[ROUNDS, 2]
        s3 ^= rks[ROUNDS, 3]

        out[i, 0] = s0
        out[i, 1] = s1
        out[i, 2] = s2
        out[i, 3] = s3

    return out


@njit(cache=True)
def _decrypt_bulk(k0, k1, k2, k3, blocks):
    out = np.empty_like(blocks)
    rks = _key_schedule_jit(k0, k1, k2, k3)

    for i in range(blocks.shape[0]):
        s0 = blocks[i, 0]
        s1 = blocks[i, 1]
        s2 = blocks[i, 2]
        s3 = blocks[i, 3]

        s0 ^= rks[ROUNDS, 0]
        s1 ^= rks[ROUNDS, 1]
        s2 ^= rks[ROUNDS, 2]
        s3 ^= rks[ROUNDS, 3]

        for r in range(ROUNDS - 1, -1, -1):
            s1 = uint16((s1 >> uint16(1))  | (s1 << uint16(15)))
            s2 = uint16((s2 >> uint16(12)) | (s2 << uint16(4)))
            s3 = uint16((s3 >> uint16(13)) | (s3 << uint16(3)))

            s0 = _sub_nibbles_16(s0, SBOX_INV)
            s1 = _sub_nibbles_16(s1, SBOX_INV)
            s2 = _sub_nibbles_16(s2, SBOX_INV)
            s3 = _sub_nibbles_16(s3, SBOX_INV)

            s0 ^= rks[r, 0]
            s1 ^= rks[r, 1]
            s2 ^= rks[r, 2]
            s3 ^= rks[r, 3]

        out[i, 0] = s0
        out[i, 1] = s1
        out[i, 2] = s2
        out[i, 3] = s3

    return out


def _key_words(key: bytes):
    k0 = int.from_bytes(key[0:4],  'little')
    k1 = int.from_bytes(key[4:8],  'little')
    k2 = int.from_bytes(key[8:12], 'little')
    k3 = int.from_bytes(key[12:16],'little')
    return np.uint32(k0), np.uint32(k1), np.uint32(k2), np.uint32(k3)


def encrypt(key: bytes, data: bytes) -> bytes:
    k0, k1, k2, k3 = _key_words(key)
    data = pkcs7_pad(data, BLOCK_SIZE)
    arr  = np.frombuffer(data, dtype=np.uint16).reshape(-1, 4).copy()
    return _encrypt_bulk(k0, k1, k2, k3, arr).tobytes()


def decrypt(key: bytes, data: bytes) -> bytes:
    k0, k1, k2, k3 = _key_words(key)
    arr = np.frombuffer(data, dtype=np.uint16).reshape(-1, 4).copy()
    return pkcs7_unpad(_decrypt_bulk(k0, k1, k2, k3, arr).tobytes())