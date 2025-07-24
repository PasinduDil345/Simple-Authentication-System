from flask import Flask, request, render_template, redirect, url_for, flash
import sqlite3
import hashlib
import jwt
from datetime import datetime, timedelta
from functools import wraps

# Create Flask app instance
app = Flask(__name__)
app.secret_key = 'simple_secret_key'  # Used for flash messages

# JWT Secret Key (used to sign JWTs)
JWT_SECRET = 'simple_secret_key'  # ⚠️ In production, use a secure key!

# Function to initialize the SQLite database
def init_db():
    # Connect to (or create) the users.db SQLite database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Create a table named 'users' if it doesn't already exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')

    # Save changes and close the connection
    conn.commit()
    conn.close()

# Run the database init function and start the Flask app
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
# Function to generate a JWT token
def create_token(username):
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token


# Decorator to protect routes that require login
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')

        if not token:
            flash("Please log in to access this page.")
            return redirect(url_for('login'))

        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.username = decoded['username']
        except jwt.ExpiredSignatureError:
            flash("Session expired. Please log in again.")
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            flash("Invalid session. Please log in again.")
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated
# Home Route
@app.route('/')
def home():
    return render_template('home.html')


# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.')
            return render_template('register.html')

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')
            return render_template('register.html')
        finally:
            conn.close()

    return render_template('register.html')


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            token = create_token(username)
            resp = redirect(url_for('protected'))
            resp.set_cookie('token', token, httponly=True)
            flash('Login successful!')
            return resp
        else:
            flash('Invalid username or password.')
            return render_template('login.html')

    return render_template('login.html')


# Protected Route
@app.route('/protected')
@token_required
def protected():
    return render_template('protected.html', username=request.username)
if __name__ == '__main__':
    init_db()
    print(">>> Flask is starting on port 3000...")
    app.run(debug=True, port=3000)

