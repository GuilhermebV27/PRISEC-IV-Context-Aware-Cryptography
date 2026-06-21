from tinyec import registry
import secrets
import hashlib


def get_curve():
    return registry.get_curve("secp256r1")


def generate_keypair(curve):
    private_key = secrets.randbelow(curve.field.n)
    public_key = private_key * curve.g
    return private_key, public_key


def ecdh(private_key, public_key):
    shared_point = private_key * public_key
    return shared_point.x


def get_shared_key(key_size=16):
    curve = get_curve()
    priv_a, pub_a = generate_keypair(curve)
    priv_b, pub_b = generate_keypair(curve)
    shared_secret = ecdh(priv_a, pub_b)
    key_bytes = hashlib.sha256(
        shared_secret.to_bytes(32, "big")
    ).digest()
    return key_bytes[:key_size]