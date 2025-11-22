
import hashlib

def sha256(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()

def hexdigest(message: bytes) -> str:
    return hashlib.sha256(message).hexdigest()
