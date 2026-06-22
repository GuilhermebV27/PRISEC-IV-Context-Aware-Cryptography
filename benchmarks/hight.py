from utils import pkcs7_pad, pkcs7_unpad
import numpy as np
from numba import njit, uint8, uint32, prange

BLOCK_SIZE = 8
_M = 0xFF

def _gen_delta():
    s = [0] * 256
    s[0]=0; s[1]=1; s[2]=0; s[3]=1; s[4]=1; s[5]=0; s[6]=1
    d = [s[6]*64 + s[5]*32 + s[4]*16 + s[3]*8 + s[2]*4 + s[1]*2 + s[0]]
    for i in range(1, 128):
        s[i+6] = s[i+2] ^ s[i-1]
        d.append(s[i+6]*64 + s[i+5]*32 + s[i+4]*16 + s[i+3]*8 + s[i+2]*4 + s[i+1]*2 + s[i])
    return d

_DELTA_PY = _gen_delta()
_DELTA_NP  = np.array(_DELTA_PY, dtype=np.uint8)


def _key_schedule_np(mk_bytes: bytes):
    """Returns wk (8,) and sk (128,) as numpy uint8 arrays."""
    K = np.frombuffer(bytes(reversed(mk_bytes)), dtype=np.uint8).copy()
    wk = np.empty(8, dtype=np.uint8)
    wk[0:4] = K[12:16]
    wk[4:8] = K[0:4]
    sk = np.empty(128, dtype=np.uint8)
    delta = _DELTA_NP
    for i in range(8):
        for j in range(8):
            sk[16*i+j]   = (int(K[(j - i) % 8])       + int(delta[16*i+j]))   & 0xFF
            sk[16*i+j+8] = (int(K[((j - i) % 8) + 8]) + int(delta[16*i+j+8])) & 0xFF
    return wk, sk

@njit(cache=True)
def _rol8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF

@njit(cache=True)
def _F0(x):
    return (_rol8(x, 1) ^ _rol8(x, 2) ^ _rol8(x, 7)) & 0xFF

@njit(cache=True)
def _F1(x):
    return (_rol8(x, 3) ^ _rol8(x, 4) ^ _rol8(x, 6)) & 0xFF

@njit(cache=True)
def _enc_core(state, wk, sk):
    """state: uint8[8] in RFC order (P0…P7), modified in-place → C0…C7."""
    x0 = uint8((uint32(state[0]) + uint32(wk[0])) & 0xFF)
    x1 = state[1]
    x2 = state[2] ^ wk[1]
    x3 = state[3]
    x4 = uint8((uint32(state[4]) + uint32(wk[2])) & 0xFF)
    x5 = state[5]
    x6 = state[6] ^ wk[3]
    x7 = state[7]

    for i in range(31):
        t0 = uint8(x7 ^ uint8((uint32(_F0(x6)) + uint32(sk[4*i+3])) & 0xFF))
        t1 = x0
        t2 = uint8((uint32(x1) + uint32(_F1(x0) ^ sk[4*i])) & 0xFF)
        t3 = x2
        t4 = uint8(x3 ^ uint8((uint32(_F0(x2)) + uint32(sk[4*i+1])) & 0xFF))
        t5 = x4
        t6 = uint8((uint32(x5) + uint32(_F1(x4) ^ sk[4*i+2])) & 0xFF)
        t7 = x6
        x0=t0; x1=t1; x2=t2; x3=t3; x4=t4; x5=t5; x6=t6; x7=t7

    t1 = uint8((uint32(x1) + uint32(_F1(x0) ^ sk[124])) & 0xFF)
    t3 = uint8(x3 ^ uint8((uint32(_F0(x2)) + uint32(sk[125])) & 0xFF))
    t5 = uint8((uint32(x5) + uint32(_F1(x4) ^ sk[126])) & 0xFF)
    t7 = uint8(x7 ^ uint8((uint32(_F0(x6)) + uint32(sk[127])) & 0xFF))
    x1=t1; x3=t3; x5=t5; x7=t7

    x0 = uint8((uint32(x0) + uint32(wk[4])) & 0xFF)
    x2 = x2 ^ wk[5]
    x4 = uint8((uint32(x4) + uint32(wk[6])) & 0xFF)
    x6 = x6 ^ wk[7]

    state[0]=x0; state[1]=x1; state[2]=x2; state[3]=x3
    state[4]=x4; state[5]=x5; state[6]=x6; state[7]=x7


@njit(cache=True)
def _dec_core(state, wk, sk):
    """state: uint8[8] in RFC order (C0…C7), modified in-place → P0…P7."""
    x0 = uint8((uint32(state[0]) - uint32(wk[4])) & 0xFF)
    x1 = state[1]
    x2 = state[2] ^ wk[5]
    x3 = state[3]
    x4 = uint8((uint32(state[4]) - uint32(wk[6])) & 0xFF)
    x5 = state[5]
    x6 = state[6] ^ wk[7]
    x7 = state[7]

    t1 = uint8((uint32(x1) - uint32(_F1(x0) ^ sk[124])) & 0xFF)
    t3 = uint8(x3 ^ uint8((uint32(_F0(x2)) + uint32(sk[125])) & 0xFF))
    t5 = uint8((uint32(x5) - uint32(_F1(x4) ^ sk[126])) & 0xFF)
    t7 = uint8(x7 ^ uint8((uint32(_F0(x6)) + uint32(sk[127])) & 0xFF))
    x1=t1; x3=t3; x5=t5; x7=t7

    for i in range(30, -1, -1):
        t0 = x1
        t1 = uint8((uint32(x2) - uint32(_F1(x1) ^ sk[4*i])) & 0xFF)
        t2 = x3
        t3 = uint8(x4 ^ uint8((uint32(_F0(x3)) + uint32(sk[4*i+1])) & 0xFF))
        t4 = x5
        t5 = uint8((uint32(x6) - uint32(_F1(x5) ^ sk[4*i+2])) & 0xFF)
        t6 = x7
        t7 = uint8(x0 ^ uint8((uint32(_F0(x7)) + uint32(sk[4*i+3])) & 0xFF))
        x0=t0; x1=t1; x2=t2; x3=t3; x4=t4; x5=t5; x6=t6; x7=t7

    x0 = uint8((uint32(x0) - uint32(wk[0])) & 0xFF)
    x2 = x2 ^ wk[1]
    x4 = uint8((uint32(x4) - uint32(wk[2])) & 0xFF)
    x6 = x6 ^ wk[3]

    state[0]=x0; state[1]=x1; state[2]=x2; state[3]=x3
    state[4]=x4; state[5]=x5; state[6]=x6; state[7]=x7

@njit(cache=True, parallel=True)
def _bulk_encrypt(blocks, wk, sk):
    """blocks: uint8[N, 8] in RFC byte order — modified in-place."""
    n = blocks.shape[0]
    for b in prange(n):
        _enc_core(blocks[b], wk, sk)

@njit(cache=True, parallel=True)
def _bulk_decrypt(blocks, wk, sk):
    """blocks: uint8[N, 8] in RFC byte order — modified in-place."""
    n = blocks.shape[0]
    for b in prange(n):
        _dec_core(blocks[b], wk, sk)

def _prepare_blocks(data: bytes) -> np.ndarray:
    """Convert a byte string to uint8[N, 8] in RFC state order (reversed)."""
    arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 8).copy()
    return arr[:, ::-1]

def _finalise_blocks(blocks: np.ndarray) -> bytes:
    """Convert uint8[N, 8] RFC state order back to a flat byte string."""
    return blocks[:, ::-1].tobytes()

def _encrypt_block(mk_bytes, block_bytes):
    wk, sk = _key_schedule_np(bytes(mk_bytes))
    state  = np.array(list(reversed(block_bytes)), dtype=np.uint8)
    _enc_core(state, wk, sk)
    return list(reversed(state.tolist()))

def _decrypt_block(mk_bytes, block_bytes):
    wk, sk = _key_schedule_np(bytes(mk_bytes))
    state  = np.array(list(reversed(block_bytes)), dtype=np.uint8)
    _dec_core(state, wk, sk)
    return list(reversed(state.tolist()))

def encrypt(key: bytes, data: bytes) -> bytes:
    data   = pkcs7_pad(data, BLOCK_SIZE)
    wk, sk = _key_schedule_np(key)
    blocks = _prepare_blocks(data)
    _bulk_encrypt(blocks, wk, sk)
    return _finalise_blocks(blocks)


def decrypt(key: bytes, data: bytes) -> bytes:
    wk, sk = _key_schedule_np(key)
    blocks = _prepare_blocks(data)
    _bulk_decrypt(blocks, wk, sk)
    return pkcs7_unpad(_finalise_blocks(blocks))