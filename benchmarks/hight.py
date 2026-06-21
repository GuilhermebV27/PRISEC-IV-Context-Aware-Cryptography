from utils import pkcs7_pad, pkcs7_unpad

BLOCK_SIZE = 8  # bytes (64 bits)
_M = 0xFF       # mod 256 mask

def _rol8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & _M

def _F0(x: int) -> int:
    return _rol8(x, 1) ^ _rol8(x, 2) ^ _rol8(x, 7)

def _F1(x: int) -> int:
    return _rol8(x, 3) ^ _rol8(x, 4) ^ _rol8(x, 6)

def _gen_delta() -> list:
    """Generate 128 LFSR constants (delta_0..delta_127)."""
    s = [0] * 256
    s[0]=0; s[1]=1; s[2]=0; s[3]=1; s[4]=1; s[5]=0; s[6]=1
    d = [s[6]*64 + s[5]*32 + s[4]*16 + s[3]*8 + s[2]*4 + s[1]*2 + s[0]]
    for i in range(1, 128):
        s[i + 6] = s[i + 2] ^ s[i - 1]
        d.append(s[i+6]*64 + s[i+5]*32 + s[i+4]*16 + s[i+3]*8 + s[i+2]*4 + s[i+1]*2 + s[i])
    return d

_DELTA = _gen_delta()

def _key_schedule(mk: list) -> tuple:
    wk = [mk[i + 12] for i in range(4)] + [mk[i] for i in range(4)]
    sk = [0] * 128
    for i in range(8):
        for j in range(8):
            sk[16*i + j]     = (mk[(j - i) % 8]       + _DELTA[16*i + j])     & _M
            sk[16*i + j + 8] = (mk[((j - i) % 8) + 8] + _DELTA[16*i + j + 8]) & _M
    return wk, sk

def _encrypt_block(mk: list, block: list) -> list:
    wk, sk = _key_schedule(mk)
    x = [0] * 8
    x[0] = (block[0] + wk[0]) & _M;  x[1] = block[1]
    x[2] =  block[2] ^ wk[1];        x[3] = block[3]
    x[4] = (block[4] + wk[2]) & _M;  x[5] = block[5]
    x[6] =  block[6] ^ wk[3];        x[7] = block[7]

    for i in range(31):
        t = [0] * 8
        t[0] = x[7] ^ ((_F0(x[6]) + sk[4*i + 3]) & _M)
        t[1] = x[0]
        t[2] = (x[1] + (_F1(x[0]) ^ sk[4*i])) & _M
        t[3] = x[2]
        t[4] = x[3] ^ ((_F0(x[2]) + sk[4*i + 1]) & _M)
        t[5] = x[4]
        t[6] = (x[5] + (_F1(x[4]) ^ sk[4*i + 2])) & _M
        t[7] = x[6]
        x = t

    t = [0] * 8
    t[0] = x[0]
    t[1] = (x[1] + (_F1(x[0]) ^ sk[124])) & _M
    t[2] = x[2]
    t[3] = x[3] ^ ((_F0(x[2]) + sk[125]) & _M)
    t[4] = x[4]
    t[5] = (x[5] + (_F1(x[4]) ^ sk[126])) & _M
    t[6] = x[6]
    t[7] = x[7] ^ ((_F0(x[6]) + sk[127]) & _M)
    x = t

    c = [0] * 8
    c[0] = (x[0] + wk[4]) & _M;  c[1] = x[1]
    c[2] =  x[2] ^ wk[5];        c[3] = x[3]
    c[4] = (x[4] + wk[6]) & _M;  c[5] = x[5]
    c[6] =  x[6] ^ wk[7];        c[7] = x[7]
    return c


def _decrypt_block(mk: list, block: list) -> list:
    wk, sk = _key_schedule(mk)
    x = [0] * 8
    x[0] = (block[0] - wk[4]) & _M;  x[1] = block[1]
    x[2] =  block[2] ^ wk[5];        x[3] = block[3]
    x[4] = (block[4] - wk[6]) & _M;  x[5] = block[5]
    x[6] =  block[6] ^ wk[7];        x[7] = block[7]

    t = [0] * 8
    t[0] = x[0]
    t[1] = (x[1] - (_F1(x[0]) ^ sk[124])) & _M
    t[2] = x[2]
    t[3] = x[3] ^ ((_F0(x[2]) + sk[125]) & _M)
    t[4] = x[4]
    t[5] = (x[5] - (_F1(x[4]) ^ sk[126])) & _M
    t[6] = x[6]
    t[7] = x[7] ^ ((_F0(x[6]) + sk[127]) & _M)
    x = t

    for i in range(30, -1, -1):
        t = [0] * 8
        t[0] = x[1]
        t[1] = (x[2] - (_F1(x[1]) ^ sk[4*i])) & _M
        t[2] = x[3]
        t[3] = x[4] ^ ((_F0(x[3]) + sk[4*i + 1]) & _M)
        t[4] = x[5]
        t[5] = (x[6] - (_F1(x[5]) ^ sk[4*i + 2])) & _M
        t[6] = x[7]
        t[7] = x[0] ^ ((_F0(x[7]) + sk[4*i + 3]) & _M)
        x = t

    p = [0] * 8
    p[0] = (x[0] - wk[0]) & _M;  p[1] = x[1]
    p[2] =  x[2] ^ wk[1];        p[3] = x[3]
    p[4] = (x[4] - wk[2]) & _M;  p[5] = x[5]
    p[6] =  x[6] ^ wk[3];        p[7] = x[7]
    return p

def encrypt(key: bytes, data: bytes) -> bytes:
    mk   = list(key)
    data = pkcs7_pad(data, BLOCK_SIZE)
    out  = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = list(data[i:i + BLOCK_SIZE])
        out.extend(_encrypt_block(mk, block))
    return bytes(out)


def decrypt(key: bytes, data: bytes) -> bytes:
    mk  = list(key)
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = list(data[i:i + BLOCK_SIZE])
        out.extend(_decrypt_block(mk, block))
    return pkcs7_unpad(bytes(out))