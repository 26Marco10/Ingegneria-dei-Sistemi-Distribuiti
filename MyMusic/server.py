from flask import Flask, request, redirect, render_template, jsonify, make_response, session
from flask_session import Session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
import requests
import base64
from functools import wraps

app = Flask(__name__)

# Configura Flask-Session
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'  # Puoi usare 'redis', 'memcached', ecc.
Session(app)

client_id = os.getenv("CLIENT_ID")
client_secret = os.getenv("CLIENT_SECRET")

DATABASE = 'ing.db'
SECRET_KEY = 'your_secret_key'

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

def get_token():
    auth_string = f"{client_id}:{client_secret}"
    auth_bytes = auth_string.encode('utf-8')
    auth_base64 = str(base64.b64encode(auth_bytes), "utf-8")

    url = "https://accounts.spotify.com/api/token"
    headers = {
        "Authorization": f"Basic {auth_base64}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "grant_type": "client_credentials"
    }

    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()
    json_result = response.json()
    return json_result["access_token"]

def get_auth_header(token):
    return {
        "Authorization": f"Bearer {token}"
    }

def search_for_playlist(token, playlist_name):
    url = "https://api.spotify.com/v1/search"
    headers = get_auth_header(token)
    params = {
        "q": playlist_name,
        "type": "playlist",
        "limit": "15"
    }

    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    json_result = response.json()["playlists"]["items"]

    if not json_result:
        print("No playlist found")
        return None

    return json_result

def get_playlist_songs(token, playlist_id):
    url = f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks"
    headers = get_auth_header(token)
    params = {
        "limit": "100"
    }

    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()["items"]

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
            return render_template('home.html', error="Utente registrato con successo!")
        except sqlite3.IntegrityError:
            return render_template('home.html', error="Username già esistente!")
        finally:
            conn.close()
        
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
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
                'username': username,  # Include l'username nel payload del token
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, SECRET_KEY, algorithm='HS256')

            expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            cursor.execute('INSERT INTO tokens (user_id, token, expires_at) VALUES (?, ?, ?)', 
                           (user_id, token, expires_at))
            conn.commit()

            session['username'] = username  # Salva l'username nella sessione
            response = make_response(redirect('/personal'))
            response.set_cookie('jwt_token', token)
            conn.close()
            return response
        else:
            conn.close()
            return render_template('home.html', error="Credenziali non valide!")

    return render_template('home.html')

def token_required(f):
    @wraps(f)
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
                           (token, user_id, datetime.datetime.utcnow()))
            token_record = cursor.fetchone()
            conn.close()

            if not token_record:
                return jsonify({'message': 'Token is invalid or expired!'}), 401

            return f(user_id, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return render_template('home.html', error="Token scaduto!")
        except jwt.InvalidTokenError:
            return render_template('home.html', error="Token non valido!")
    return decorator

@app.route('/personal', methods=['GET'])
@token_required
def personal(user_id):
    # Ottieni l'username dalla sessione
    username = session.get('username')

    spotify_token = get_token()
    playlists = search_for_playlist(spotify_token, "Top 50 Italia")
    image_url = "https://icpapagiovanni.edu.it/wp-content/uploads/2017/11/musica-1.jpg"
    playlists_data = []
    for playlist in playlists:
        if playlist["images"]:
            image_url = playlist["images"][0]["url"]
        playlist_data = {
            "name": playlist["name"],
            "id": playlist["id"],
            "image": image_url,
            "name": playlist["name"]
        }
        playlists_data.append(playlist_data)

    return render_template('personal.html', username=username, playlists=playlists_data)

@app.route('/search', methods=['GET','POST'])
@token_required
def search(user_id):
    # Ottieni l'username dalla sessione
    username = session.get('username')

    spotify_token = get_token()
    if request.method == 'GET':
        return render_template('search.html', username=username)
    search_query = request.form['search_query']
    playlists = search_for_playlist(spotify_token, search_query)
    image_url = "https://icpapagiovanni.edu.it/wp-content/uploads/2017/11/musica-1.jpg"
    playlists_data = []
    for playlist in playlists:
        if playlist["images"]:
            image_url = playlist["images"][0]["url"]
        playlist_data = {
            "name": playlist["name"],
            "id": playlist["id"],
            "image": image_url,
            "name": playlist["name"]
        }
        playlists_data.append(playlist_data)

    return render_template('search.html', username=username, playlists=playlists_data, search_query=search_query)

@app.route('/playlist/<playlist_id>/<playlist_name>', methods=['GET'])
@token_required
def playlist(user_id, playlist_id, playlist_name):
    # Ottieni l'username dalla sessione
    username = session.get('username')

    spotify_token = get_token()
    songs = get_playlist_songs(spotify_token, playlist_id)
    songs_data = []
    for song in songs:
        song_data = {
            "name": song["track"]["name"],
            "artist": song["track"]["artists"][0]["name"],
            "image": song["track"]["album"]["images"][0]["url"]
        }
        songs_data.append(song_data)

    return render_template('playlist.html', username=username, songs=songs_data, playlist_name=playlist_name)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)
