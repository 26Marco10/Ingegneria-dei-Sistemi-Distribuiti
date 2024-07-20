from flask import Flask, request, redirect, render_template, jsonify, make_response
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

app = Flask(__name__)

# Configurazione del database
DATABASE = 'ing.db'

# Configurazione della chiave segreta per i token JWT
SECRET_KEY = 'your_secret_key'  # Cambia questa chiave con una chiave segreta sicura

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already taken", 400
        finally:
            conn.close()
        
        return redirect('/success')
    return render_template('home.html')

@app.route('/success')
def success():
    return "Registrazione avvenuta con successo!"

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            user_id = user['id']
            token = jwt.encode({
                'user_id': user_id,
                'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
            }, SECRET_KEY, algorithm='HS256')

            # Salva il token nel database
            expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
            cursor.execute('INSERT INTO tokens (user_id, token, expires_at) VALUES (?, ?, ?)', 
                           (user_id, token, expires_at))
            conn.commit()

            response = make_response(redirect('/login-success'))
            response.set_cookie('jwt_token', token, httponly=True, secure=True, samesite='Lax')
            conn.close()
            return response
        else:
            conn.close()
            return redirect('/login-failed')
    return render_template('home.html')

@app.route('/login-success')
def login_success():
    return "Login effettuato con successo!"

@app.route('/login-failed')
def login_failed():
    return "Login fallito!"

def token_required(f):
    def decorator(*args, **kwargs):
        token = request.cookies.get('jwt_token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id = data['user_id']

            # Verifica se il token esiste nel database e non è scaduto
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM tokens WHERE token = ? AND user_id = ? AND expires_at > ?', 
                           (token, user_id, datetime.datetime.now(datetime.UTC)))
            token_record = cursor.fetchone()
            conn.close()

            if not token_record:
                return jsonify({'message': 'Token is invalid or expired!'}), 401

            return f(user_id, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
    return decorator

@app.route('/protected', methods=['GET'])
@token_required
def protected(user_id):
    return f'Hello, user {user_id}! This is a protected route.'


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)
