import sqlite3
import bcrypt
import requests
import string
import secrets  
from urllib.parse import urlparse, parse_qs
from flask import Flask, render_template, request, redirect, url_for, session, g

app = Flask(__name__)

app.config['SECRET_KEY'] = secrets.token_hex(16)
DATABASE = 'database.db'

def get_db():
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = sqlite3.connect(DATABASE)
    return g.sqlite_db

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('init.sql', mode='r') as f:
            db.cursor().executescript(f.read())

        alphabet = string.ascii_letters + string.digits
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('developer', 'developer_password'))
        
        internal_admin_password = ''.join(secrets.choice(alphabet) for i in range(20))
        hashed_password = bcrypt.hashpw(internal_admin_password.encode('utf-8'), bcrypt.gensalt())
        db.execute("INSERT INTO internal_users (username, password_hash) VALUES (?, ?)", ('admin', hashed_password.decode('utf-8')))

        db.commit()

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        db = get_db()
        cur = db.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                         [request.form['username'], request.form['password']])
        user = cur.fetchone()
        if user:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/api_tester', methods=['POST'])
def api_tester():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    url = request.form.get('url')
    content = request.form.get('content')
    response_text = ""

    try:
        parsed_url = urlparse(url)
        if parsed_url.hostname == 'certainweb.com':
            post_data = {k: v[0] for k, v in parse_qs(content).items()}
            res = requests.post(url, data=post_data, timeout=3)
            response_text = res.text
        else:
            response_text = "Error: URL must be for our partner, certainweb.com"
    except Exception as e:
        response_text = f"An error occurred: {e}"

    return render_template('dashboard.html', response_text=response_text)

@app.route('/internal_login', methods=['GET', 'POST'])
def internal_login():
    if request.remote_addr != '127.0.0.1':
        return "Forbidden: This resource is only available internally.", 403

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = get_db()
        
        query = f"SELECT * FROM internal_users WHERE username = '{username}'"
        
        try:
            cur = db.execute(query)
            user_record = cur.fetchone()

            if user_record:
                password_hash_from_db = user_record[2].encode('utf-8')
                if bcrypt.checkpw(password.encode('utf-8'), password_hash_from_db):
                    return render_template('flag.html')
                else:
                    return "Internal Authentication Failed: Incorrect Password"
            else:
                return "Internal Authentication Failed: User not found"
        except Exception as e:
            return f"Database error: {e}"

    return render_template('internal.html')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=80)