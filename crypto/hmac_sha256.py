
from .sha256 import sha256
import binascii

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    block_size = 64
    if len(key) > block_size:
        key = sha256(key)
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))
    o_key_pad = bytes((b ^ 0x5c) for b in key)
    i_key_pad = bytes((b ^ 0x36) for b in key)
    inner = sha256(i_key_pad + message)
    outer = sha256(o_key_pad + inner)
    return outer

def hexdigest(key: bytes, message: bytes) -> str:
    return binascii.hexlify(hmac_sha256(key, message)).decode()
