from flask import Flask, request, redirect, send_file, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('register.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Qui puoi aggiungere il codice per salvare i dati nel database
        
        print(f"Username: {username}")
        print(f"Password: {password}")
        
        return redirect('/success')
    return render_template('register.html')

@app.route('/success')
def success():
    return "Registrazione avvenuta con successo!"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)