from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'ваш_секретный_ключ'
app.config['DATABASE'] = 'site.db'

login_manager = LoginManager(app)
login_manager.login_view = 'auth'

class User(UserMixin):
    def __init__(self, id_, username, is_admin=False):
        self.id = id_
        self.username = username
        self.is_admin = is_admin

def init_db():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                equipment_type TEXT NOT NULL,
                model_number TEXT NOT NULL,
                problem_description TEXT NOT NULL,
                urgency TEXT NOT NULL,
                status TEXT DEFAULT 'Новая',
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        admin = cursor.execute('SELECT * FROM users WHERE username = "admin"').fetchone()
        if not admin:
            hashed_password = generate_password_hash('admin123')
            cursor.execute('INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
                           ('admin', 'admin@example.com', hashed_password, True))
        conn.commit()

init_db()

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user:
            return User(user['id'], user['username'], user['is_admin'])
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth')
def auth():
    return render_template('auth.html')

@app.route('/api/requests', methods=['GET', 'POST'])
@login_required
def handle_requests():
    if request.method == 'POST':
        data = request.get_json()
        try:
            with sqlite3.connect(app.config['DATABASE']) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO requests 
                    (equipment_type, model_number, problem_description, urgency, user_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (data['equipmentType'], data['modelNumber'], data['problemDescription'], 
                     data['urgency'], current_user.id))
                conn.commit()
                new_id = cursor.lastrowid
                return jsonify({
                    'id': new_id,
                    'status': 'Новая',
                    'created_at': datetime.now().strftime('%d.%m.%Y')
                }), 201
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        with sqlite3.connect(app.config['DATABASE']) as conn:
            conn.row_factory = sqlite3.Row
            requests = conn.execute('''
                SELECT *, strftime('%d.%m.%Y', created_at) as created_at 
                FROM requests WHERE user_id = ?
            ''', (current_user.id,)).fetchall()
            return jsonify([dict(row) for row in requests])

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute('SELECT * FROM users WHERE username = ?', (data['username'],)).fetchone()
    
    if user and check_password_hash(user['password'], data['password']):
        user_obj = User(user['id'], user['username'], user['is_admin'])
        login_user(user_obj)
        return jsonify({'success': True, 'is_admin': user['is_admin']})
    return jsonify({'success': False}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    try:
        hashed_password = generate_password_hash(data['password'])
        with sqlite3.connect(app.config['DATABASE']) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, email, password)
                VALUES (?, ?, ?)
            ''', (data['username'], data['email'], hashed_password))
            conn.commit()
            return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Пользователь уже существует'}), 400

@app.route('/profile')
@login_required
def profile():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.row_factory = sqlite3.Row
        requests = conn.execute('''
            SELECT *, strftime('%d.%m.%Y', created_at) as created_at 
            FROM requests WHERE user_id = ?
        ''', (current_user.id,)).fetchall()
    return render_template('profile.html', requests=requests)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.row_factory = sqlite3.Row
        requests = conn.execute('SELECT * FROM requests').fetchall()
        users = conn.execute('SELECT * FROM users').fetchall()
    return render_template('admin.html', requests=requests, users=users)

@app.route('/update_status/<int:request_id>', methods=['POST'])
@login_required
def update_status(request_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    new_status = request.json['status']
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.execute('UPDATE requests SET status = ? WHERE id = ?', (new_status, request_id))
        conn.commit()
    return jsonify({'success': True})

@app.route('/delete_request/<int:request_id>', methods=['DELETE'])
@login_required
def delete_request(request_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.execute('DELETE FROM requests WHERE id = ?', (request_id,))
        conn.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True)