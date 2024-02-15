from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '6ce93e6e887dee4c23c6095bee96f191489d58646dde3416'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

DATABASE = 'users.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    return db

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                    (username, generate_password_hash(password, method='pbkdf2:sha256')))
        db.commit()
        
        session['username'] = username
        return redirect(url_for('index'))
        
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user[2], password):  # Assuming password is at index 2
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None) 
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    db = get_db()
    images = db.execute('SELECT * FROM images WHERE username = ?', (session['username'],)).fetchall() 
    return render_template('index.html', images=images)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        f = request.files['image']
        # Save image
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], f'{session["username"]}_{f.filename}'))
        return redirect(url_for('index'))

    return render_template('upload.html')

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
