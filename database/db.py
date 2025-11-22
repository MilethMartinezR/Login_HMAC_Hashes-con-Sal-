# database/db.py
import sqlite3
import os
import binascii
from datetime import datetime
import hashlib

DB_FILENAME = os.path.join(os.path.dirname(__file__), '..', 'users.db')

def get_conn():
    return sqlite3.connect(DB_FILENAME)

def init_db(populate=True):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    
    # Registro automático de usuarios por defecto
    if populate:
        users = [
            ('alice','AlicePass123'),
           ('bob','BobSecure456'),
            ('charlie','Charlie789!'),
            ('diana','Diana@2024'),
            ('eve','EveHacker$$'),
            ('frank','Frank#Pass1'),
            ('grace','Grace_2024'),
            ('henry','Henry!Secure'),
            ('iris','Iris@Pass99'),
            ('jack','Jack$2024!')
        ]
        for u,p in users:
            try:
                register_user(u,p,conn)
            except Exception:
                pass
    
    conn.close()

def register_user(username, password, conn=None):
    close = False
    if conn is None:
        conn = get_conn()
        close = True
    cur = conn.cursor()
    
    # Validar que el username no esté vacío
    if not username or not username.strip():
        if close:
            conn.close()
        raise ValueError("El nombre de usuario no puede estar vacío")
    
    # Validar longitud de contraseña
    if len(password) < 6:
        if close:
            conn.close()
        raise ValueError("La contraseña debe tener al menos 6 caracteres")
    
    # Generar salt aleatorio
    salt = os.urandom(32)
    
    # Calcular hash usando hashlib (librería estándar)
    p_hash = hashlib.sha256(password.encode('utf-8') + salt).digest()
    
    # Convertir a hexadecimal para almacenar
    salt_hex = binascii.hexlify(salt).decode()
    hash_hex = binascii.hexlify(p_hash).decode()
    
    ts = datetime.utcnow().isoformat() + 'Z'
    
    try:
        cur.execute('''
            INSERT INTO users (username, password_hash, salt, created_at)
            VALUES (?, ?, ?, ?)
        ''', (username, hash_hex, salt_hex, ts))
        
        conn.commit()
    except sqlite3.IntegrityError as e:
        if close:
            conn.close()
        if 'UNIQUE constraint failed: users.username' in str(e):
            raise ValueError(f"El usuario '{username}' ya está registrado")
        else:
            raise ValueError("Error al registrar el usuario")
    except Exception as e:
        if close:
            conn.close()
        raise ValueError(f"Error inesperado: {str(e)}")
    
    if close:
        conn.close()

def list_users():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT id, username, password_hash, salt, created_at FROM users ORDER BY id')
    rows = cur.fetchall()
    conn.close()
    return rows
