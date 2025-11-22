import os
import sqlite3
import binascii
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash
from services.hmac_service import sign_message, verify_message
from database.db import init_db, list_users
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

app = Flask(__name__)
app.secret_key = os.urandom(16)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        from database.db import register_user
        try:
            register_user(username, password)
            flash(f'Usuario {username} registrado exitosamente', 'success')
        except ValueError as e:
            flash(f'{str(e)}', 'error')
        except Exception as e:
            flash(f'Error al registrar usuario. Intenta nuevamente.', 'error')
        return redirect(url_for('index'))
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register_route():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        from database.db import register_user
        try:
            register_user(username, password)
            flash(f'Usuario {username} registrado exitosamente', 'success')
        except ValueError as e:
            flash(f'{str(e)}', 'error')
        except Exception as e:
            flash(f'Error al registrar usuario. Intenta nuevamente.', 'error')
        return redirect(url_for('register_route'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hmac_manual = request.form.get('hmac_manual', '').strip()
        
        # PASO 1: Recuperar (hash_almacenado, salt) de BD
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT salt, password_hash FROM users WHERE username = ?', (username,))
        row = c.fetchone()
        conn.close()
        
        if not row:
            # Timestamp cuando el usuario no existe
            ts = datetime.utcnow().isoformat() + "Z"
            print("\n")
            print("INTENTO DE AUTENTICACIÓN FALLIDO")
            print("\n")
            print(f"Usuario:              {username}")
            print(f"Timestamp:            {ts}")
            print(f"Razón:                Contraseña incorrecta")
            print("\n")
            
            flash('Usuario no existe', 'error')
            return render_template('login.html')
        
        salt_hex, hash_almacenado = row
        salt = binascii.unhexlify(salt_hex)
        
        # PASO 2: Calcular hash_intento = SHA256(password + salt) usando hashlib
        hash_intento_bytes = hashlib.sha256(password.encode('utf-8') + salt).digest()
        hash_intento = binascii.hexlify(hash_intento_bytes).decode()
        
        # PASO 3: Verificar hash_intento == hash_almacenado
        if hash_intento != hash_almacenado:
            # Timestamp cuando la contraseña es incorrecta
            ts = datetime.utcnow().isoformat() + "Z"
            print("\n")
            print("INTENTO DE AUTENTICACIÓN FALLIDO")
            print("\n")
            print(f"Usuario:              {username}")
            print(f"Timestamp:            {ts}")
            print(f"Razón:                Contraseña incorrecta")
            print("\n")
            
            flash('Usuario o contraseña incorrectos', 'error')
            return render_template('login.html')
        
        # PASO 4: Generar mensaje de autenticación y su HMAC
        ts = datetime.utcnow().isoformat() + "Z"
        mensaje_autenticacion = f"{username}|{ts}"
        hmac_generado = sign_message(mensaje_autenticacion.encode('utf-8'))
        
        # PASO 5: Verificar HMAC si se proporcionó uno manual
        if hmac_manual:
            hmac_valido = verify_message(mensaje_autenticacion.encode('utf-8'), hmac_manual)
            
            # IMPRIMIR EN CONSOLA
            print("\n" )
            print("VALIDACIÓN DE HMAC")
            print("\n" )
            print(f"Usuario:              {username}")
            print(f"Mensaje:              {mensaje_autenticacion}")
            print(f"HMAC proporcionado:   {hmac_manual}")
            print(f"HMAC correcto:        {hmac_generado}")
            print(f"Resultado:            {'VÁLIDO' if hmac_valido else 'INVÁLIDO'}")
            print("\n" )
            
            
            flash(f'Usuario o contraseña incorrectos', 'error')
            return redirect('/login')
        
        # Login normal sin que el usario proporcione HMAC
        flash(f'¡Bienvenido {username}! Autenticación exitosa', 'success')
        ts = datetime.utcnow().isoformat() + "Z"
        print("\n")
        print(f"INTENTO DE AUTENTICACIÓN EXITOSO")
        print("\n")
        print(f"Usuario:              {username}")
        print(f"Timestamp:            {ts}")
        print(f'Mensaje firmado: {mensaje_autenticacion}', 'success')
        print(f'HMAC generado: {hmac_generado}', 'success')
       
        
        return redirect('/login')
    
    return render_template('login.html')

@app.route('/verify', methods=['GET','POST'])
def verify_route():
    verification = None
    default_msg = 'alice|' + datetime.utcnow().isoformat() + 'Z'
    if request.method == 'POST':
        msg = request.form['message'].encode('utf-8')
        hmac_hex = request.form['hmac_hex']
        valid = verify_message(msg, hmac_hex)
        verification = {'valid': valid, 'message': msg.decode(), 'hmac': hmac_hex}
    return render_template('verify.html', verification=verification, default_msg=default_msg)

@app.route('/db')
def db_route():
    rows = list_users()
    return render_template('db.html', rows=rows)

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        init_db(populate=True)
    app.run(debug=True)