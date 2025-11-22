import binascii
from database.db import get_user, register_user
from crypto.sha256 import sha256

def register(username, password):
    register_user(username, password)

def authenticate(username, password_attempt):
    row = get_user(username)
    if not row:
        return False, {'reason':'usuario no encontrado'}
    _id, uname, stored_hash_hex, salt_hex, created = row
    salt = binascii.unhexlify(salt_hex)
    computed = sha256(password_attempt.encode('utf-8') + salt)
    if binascii.hexlify(computed).decode() == stored_hash_hex:
        return True, {'id':_id, 'username':uname, 'created_at':created}
    return False, {'reason':'contraseña incorrecta'}
