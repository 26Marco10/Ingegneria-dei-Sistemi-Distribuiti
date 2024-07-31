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
app.config['SESSION_TYPE'] = 'filesystem'  
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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS playlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            playlist_id TEXT NOT NULL,
            img_url TEXT NOT NULL,
            name TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    #crea una tabella dove vengono salvate le canzoni preferite dall'utente
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS songs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            img_url TEXT NOT NULL,
            name TEXT NOT NULL,
            artist TEXT NOT NULL,
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

def get_playlist_by_id(token, playlist_id):
    url = f"https://api.spotify.com/v1/playlists/{playlist_id}"
    headers = get_auth_header(token)

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


def get_count_songs_in_top50italy(user_id, token):
    italy_top50_id = "37i9dQZEVXbIQnj7RRhdSX"
    top50_songs = get_playlist_songs(token, italy_top50_id)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM songs WHERE user_id = ?', (user_id,))
    songs = cursor.fetchall()
    conn.close()
    #ritorna quali canzoni presenti nel db sono presenti nella playlist TOP 50 ITALY e la loro posizione nella classifica
    i = 0
    songs_data = []
    for song in songs:
        for top50_song in top50_songs:
            i = i+1
            if song["name"] == top50_song["track"]["name"] and song["artist"] == top50_song["track"]["artists"][0]["name"]:
                song_data = {
                    "name": song["name"],
                    "artist": song["artist"],
                    "image": song["img_url"],
                    "position": i
                }
                songs_data.append(song_data)
                break
        i = 0
    return songs_data

    

def get_count_songs_in_top50global(user_id, token):
    global_top50_id = "37i9dQZEVXbMDoHDwVN2tF"
    top50_songs = get_playlist_songs(token, global_top50_id)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM songs WHERE user_id = ?', (user_id,))
    songs = cursor.fetchall()
    conn.close()
    
    i = 0
    songs_data = []
    for song in songs:
        for top50_song in top50_songs:
            i = i+1
            if song["name"] == top50_song["track"]["name"] and song["artist"] == top50_song["track"]["artists"][0]["name"]:
                song_data = {
                    "name": song["name"],
                    "artist": song["artist"],
                    "image": song["img_url"],
                    "position": i
                }
                songs_data.append(song_data)
                break
        i = 0
    return songs_data


    
    
@app.route('/')
def home():
    #cancella la sessione e il cookie
    session.clear()
    response = make_response(render_template('home.html'))
    response.set_cookie('jwt_token', '', expires=0)
    return response


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
            session['italy_top'] = get_count_songs_in_top50italy(user_id, get_token())
            session['italy_top50'] = len(session['italy_top'])
            session['global_top'] = get_count_songs_in_top50global(user_id, get_token())
            session['global_top50'] = len(session['global_top'])
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
                #cancella la sessione e il cookie
                session.clear()
                return jsonify({'message': 'Token is invalid or expired!'}), 401
            
            # Aggiorna il token
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            new_token = jwt.encode({
                'user_id': user_id,
                'username': data['username'],
                'exp': expires_at
            }, SECRET_KEY, algorithm='HS256')

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE tokens SET token = ?, expires_at = ? WHERE id = ?', 
                           (new_token, expires_at, token_record['id']))
            conn.commit()
            conn.close()
            
            response = make_response(f(user_id, *args, **kwargs))
            response.set_cookie('jwt_token', new_token)
            return response
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

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM playlists WHERE user_id = ?', (user_id,))
    playlists = cursor.fetchall()
    conn.close()
    playlists_data = []
    for playlist in playlists:
        playlist_data = {
            "name": playlist["name"],
            "id": playlist["playlist_id"],
            "image": playlist["img_url"]
        }
        playlists_data.append(playlist_data)
    session_playlists = session.get('playlists')
    return render_template('personal.html', username=username, playlists=playlists_data, session_playlists=session_playlists, italy_top50=session['italy_top50'], global_top50=session['global_top50'])

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

    return render_template('playlist.html', username=username, songs=songs_data, playlist_name=playlist_name, playlist_id=playlist_id)

@app.route('/add_playlist', methods=['POST'])
@token_required
def add_playlist(user_id):
    data = request.get_json()
    playlist_id = data['id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM playlists WHERE playlist_id = ?', (playlist_id,))
    playlist = cursor.fetchone()
    if playlist:
        print("Playlist already added")
        conn.close()
        return jsonify({'status': 'error', 'message': 'Playlist già aggiunta!'}), 400
    playlist = get_playlist_by_id(get_token(), playlist_id)
    img_url = "https://icpapagiovanni.edu.it/wp-content/uploads/2017/11/musica-1.jpg"
    if playlist["images"]:
        img_url = playlist["images"][0]["url"]
    # Inserisci la playlist in sessione
    if 'playlists' not in session:
        session['playlists'] = []
    
    session['playlists'].append({
        'id': playlist_id,
        'name': playlist['name'],
        'image': img_url
    })
    return jsonify({'status': 'success', 'message': 'Playlist aggiunta con successo!'})

@app.route('/save_playlist/<playlistId>', methods=['GET'])
@token_required
def save_playlist(user_id, playlistId):
    spotify_token = get_token()
    playlist = get_playlist_by_id(spotify_token, playlistId)
    playlistName = playlist['name']
    playlistImage = "https://icpapagiovanni.edu.it/wp-content/uploads/2017/11/musica-1.jpg"
    if playlist["images"]:
        playlistImage = playlist["images"][0]["url"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO playlists (user_id, playlist_id, img_url, name) VALUES (?, ?, ?, ?)', 
                   (user_id, playlistId, playlistImage, playlistName))
    conn.commit()
    conn.close()
    #elimina da session['playlists'] la playlist appena salvata
    session['playlists'] = [playlist for playlist in session['playlists'] if playlist['id'] != playlistId]
    return redirect('/personal')

@app.route('/add_song', methods=['POST'])
@token_required
def add_song(user_id):
    data = request.get_json()
    song_name = data['name']
    song_artist = data['artist']
    img_url = data['image']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM songs WHERE name = ? AND artist = ? AND img_url= ? AND user_id = ?', (song_name, song_artist, img_url, user_id))
    song = cursor.fetchone()
    if song:
        print("Song already added")
        conn.close()
        return jsonify({'status': 'error', 'message': 'Canzone già aggiunta!'}), 400
    # Inserisci la canzone nel db
    cursor.execute('INSERT INTO songs (user_id, img_url, name, artist) VALUES (?, ?, ?, ?)', 
                   (user_id, img_url, song_name, song_artist))
    conn.commit()
    conn.close()
    session['italy_top'] = get_count_songs_in_top50italy(user_id, get_token())
    session['italy_top50'] = len(session['italy_top'])
    session['global_top'] = get_count_songs_in_top50global(user_id, get_token())
    session['global_top50'] = len(session['global_top'])
    return jsonify({'status': 'success', 'message': 'Canzone aggiunta con successo!'})

@app.route('/favorite', methods=['GET'])
@token_required
def favorite(user_id):
    # Ottieni l'username dalla sessione
    username = session.get('username')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM songs WHERE user_id = ?', (user_id,))
    songs = cursor.fetchall()
    conn.close()
    songs_data = []
    for song in songs:
        #se song è presente in session['italy_top'] o in session['global_top'] allora aggiungi la posizione in classifica
        position = None
        country = None
        for top50_song in session['global_top']:
            if song["name"] == top50_song["name"] and song["artist"] == top50_song["artist"]:
                position = top50_song["position"]
                country = "Global"
                break
        if position is None:
            for top50_song in session['italy_top']:
                if song["name"] == top50_song["name"] and song["artist"] == top50_song["artist"]:
                    position = top50_song["position"]
                    country = "Italy"
                    break
        
        if position is None:
            song_data = {
                "name": song["name"],
                "artist": song["artist"],
                "image": song["img_url"],
            }
        else:
            song_data = {
                "name": song["name"],
                "artist": song["artist"],
                "image": song["img_url"],
                "position": position,
                "country": country
            }
        songs_data.append(song_data)
    return render_template('favorite.html', username=username, songs=songs_data)

@app.route('/logout', methods=['GET'])
@token_required
def logout(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM tokens WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    response = make_response(redirect('/'))
    response.set_cookie('jwt_token', '', expires=0)
    return redirect('/')



if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)
