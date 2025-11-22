import hmac
import hashlib
import os

# Cargar clave desde archivo server.key
def load_server_key():
    """
    Carga la clave del servidor desde el archivo server.key
    Si no existe, usa variable de entorno o fallback
    """
    key_path = os.path.join(os.path.dirname(__file__), '..', 'server.key')
    
    
    if os.path.exists(key_path):
        with open(key_path, 'r') as f:
            key_hex = f.read().strip()
            return bytes.fromhex(key_hex)
    
    # Prioridad 2: Variable de entorno
    env_key = os.environ.get('HMAC_SERVER_KEY')
    if env_key:
        if isinstance(env_key, str):
            return env_key.encode('utf-8')
        return env_key
    
    # Prioridad 3: Fallback (solo para desarrollo)
    print("ADVERTENCIA: Usando clave por defecto. Configura server.key en producción.")
    return b'clave_super_secreta_Para?asegurar_asegurando'

SERVER_KEY = load_server_key()

    # Firma un mensaje usando HMAC-SHA256 con la clave del servidor. # pyright: ignore[reportUndefinedVariable]
    # Retorna el HMAC en formato hexadecimal.
def sign_message(message: bytes) -> str:
    h = hmac.new(SERVER_KEY, message, hashlib.sha256)
    return h.hexdigest()

# Verifica que un HMAC sea válido para un mensaje dado.
def verify_message(message: bytes, hmac_hex: str) -> bool:
    
    expected_hmac = sign_message(message)
    # Comparación contra timing attacks
    return hmac.compare_digest(expected_hmac, hmac_hex)

# Calcula HMAC-SHA256 de un mensaje con una clave dada.
def hmac_sha256(key: bytes, message: bytes) -> str:
    h = hmac.new(key, message, hashlib.sha256)
    return h.hexdigest()
