import numpy as np
from numba import njit, uint64
from utils import pkcs7_pad, pkcs7_unpad

BLOCK_SIZE = 16  # bytes (128 bits)


@njit(cache=True)
def _rotr64(x, n):
    n = uint64(n)
    return (x >> n) | (x << (uint64(64) - n))


@njit(cache=True)
def _rotl64(x, n):
    n = uint64(n)
    return (x << n) | (x >> (uint64(64) - n))


@njit(cache=True)
def _key_schedule_jit(A, B):
    """
    Mirrors: Speck128128KeySchedule(K[], rk[])
      A = K[0] (low word)
      B = K[1] (high word)
      ER64(B, A, i) → x=B, y=A
    """
    rks = np.empty(32, dtype=np.uint64)
    for i in range(31):
        rks[i] = A
        B = _rotr64(B, 8) + A
        B ^= uint64(i)
        A = _rotl64(A, 3) ^ B
    rks[31] = A
    return rks


@njit(cache=True)
def _encrypt_bulk(A, B, blocks):
    """
    Mirrors: Speck128128Encrypt
      Ct[0] = Pt[0]  → col0 = low word  (y)
      Ct[1] = Pt[1]  → col1 = high word (x)
      ER64(Ct[1], Ct[0], rk) → x=col1, y=col0
    """
    out = np.empty_like(blocks)
    rks = _key_schedule_jit(A, B)
    for i in range(blocks.shape[0]):
        y = blocks[i, 0]
        x = blocks[i, 1]
        for rk in rks:
            x = _rotr64(x, 8) + y
            x ^= rk
            y = _rotl64(y, 3) ^ x
        out[i, 0] = y
        out[i, 1] = x
    return out


@njit(cache=True)
def _decrypt_bulk(A, B, blocks):
    """
    Mirrors: Speck128128Decrypt
      DR64(Pt[1], Pt[0], rk) → x=col1, y=col0
    """
    out = np.empty_like(blocks)
    rks = _key_schedule_jit(A, B)
    for i in range(blocks.shape[0]):
        y = blocks[i, 0]
        x = blocks[i, 1]
        for j in range(31, -1, -1):
            y ^= x
            y = _rotr64(y, 3)
            x ^= rks[j]
            x -= y
            x = _rotl64(x, 8)
        out[i, 0] = y
        out[i, 1] = x
    return out


def _key_words(key: bytes):
    """K[0]=low word (first 8 bytes), K[1]=high word (last 8 bytes)."""
    A = np.frombuffer(key[0:8], dtype=np.uint64)[0]
    B = np.frombuffer(key[8:16], dtype=np.uint64)[0]
    return A, B


def _encrypt_block(key: bytes, block: bytes) -> bytes:
    """Single block encrypt — no padding."""
    A, B = _key_words(key)
    arr = np.array(
        [
            [
                np.frombuffer(block[0:8], dtype=np.uint64)[0],
                np.frombuffer(block[8:16], dtype=np.uint64)[0],
            ]
        ],
        dtype=np.uint64,
    )
    out = _encrypt_bulk(A, B, arr)
    return out[0, 0].tobytes() + out[0, 1].tobytes()


def _decrypt_block(key: bytes, block: bytes) -> bytes:
    """Single block decrypt — no padding."""
    A, B = _key_words(key)
    arr = np.array(
        [
            [
                np.frombuffer(block[0:8], dtype=np.uint64)[0],
                np.frombuffer(block[8:16], dtype=np.uint64)[0],
            ]
        ],
        dtype=np.uint64,
    )
    out = _decrypt_bulk(A, B, arr)
    return out[0, 0].tobytes() + out[0, 1].tobytes()


def encrypt(key: bytes, data: bytes) -> bytes:
    A, B = _key_words(key)
    data = pkcs7_pad(data, BLOCK_SIZE)
    arr = np.frombuffer(data, dtype=np.uint64).reshape(-1, 2).copy()
    return _encrypt_bulk(A, B, arr).tobytes()


def decrypt(key: bytes, data: bytes) -> bytes:
    A, B = _key_words(key)
    arr = np.frombuffer(data, dtype=np.uint64).reshape(-1, 2).copy()
    return pkcs7_unpad(_decrypt_bulk(A, B, arr).tobytes())
