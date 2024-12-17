from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import requests
import json
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password
        self.leetcode_username = None

# Modify the database path to work with Vercel
def get_db_path():
    if os.environ.get('VERCEL_ENV') == 'production':
        # Use /tmp directory in Vercel's environment
        return '/tmp/users.db'
    return 'users.db'

# Modify database connection function
def get_db_connection():
    db_path = get_db_path()
    # Create directory if it doesn't exist in Vercel
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

# Modify init_db function
def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            leetcode_username TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS followed_leetcode (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            leetcode_username TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, leetcode_username)
        )
    ''')
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['password'])
    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                     (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists!"
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = c.fetchone()
        conn.close()

        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data['id'], user_data['username'], user_data['password'])
            login_user(user)
            return redirect(url_for('profile'))

    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Get user's leetcode username
    c.execute('SELECT leetcode_username FROM users WHERE id = ?', (current_user.id,))
    result = c.fetchone()
    leetcode_username = result['leetcode_username'] if result else None
    
    # Get followed leetcode usernames
    c.execute('SELECT leetcode_username FROM followed_leetcode WHERE user_id = ?', (current_user.id,))
    followed_usernames = [row['leetcode_username'] for row in c.fetchall()]
    conn.close()
    
    # Get stats for user and followed users
    leetcode_stats = None
    if leetcode_username:
        leetcode_stats = get_leetcode_stats(leetcode_username)
    
    followed_stats = []
    for username in followed_usernames:
        stats = get_leetcode_stats(username)
        if stats:
            followed_stats.append(stats)
    
    return render_template('profile.html', 
                         leetcode_username=leetcode_username,
                         leetcode_stats=leetcode_stats,
                         followed_stats=followed_stats)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('login'))

def get_leetcode_stats(username):
    """Fetch LeetCode statistics for a given username"""
    url = "https://leetcode.com/graphql"
    query = """
    query getUserProfile($username: String!) {
        matchedUser(username: $username) {
            username
            submitStats: submitStatsGlobal {
                acSubmissionNum {
                    difficulty
                    count
                    submissions
                }
            }
            profile {
                ranking
                reputation
                starRating
            }
        }
    }
    """
    
    try:
        response = requests.post(url, json={
            'query': query,
            'variables': {'username': username}
        })
        
        if response.status_code == 200:
            data = response.json()
            if data.get('data', {}).get('matchedUser'):
                user_data = data['data']['matchedUser']
                stats = user_data['submitStats']['acSubmissionNum']
                total_solved = sum(item['count'] for item in stats)//2
                return {
                    'username': user_data['username'],
                    'total_solved': total_solved,
                    'easy': stats[1]['count'],
                    'medium': stats[2]['count'],
                    'hard': stats[3]['count'],
                    'ranking': user_data['profile']['ranking']
                }
        return None
    except Exception as e:
        print(f"Error fetching LeetCode stats: {e}")
        return None

@app.route('/update_leetcode', methods=['POST'])
@login_required
def update_leetcode():
    leetcode_username = request.form.get('leetcode_username')
    if not leetcode_username:
        return jsonify({'error': 'No username provided'}), 400
    
    # Verify the LeetCode username exists
    stats = get_leetcode_stats(leetcode_username)
    if not stats:
        return jsonify({'error': 'Invalid LeetCode username'}), 400
    
    # Update the database
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('UPDATE users SET leetcode_username = ? WHERE id = ?',
              (leetcode_username, current_user.id))
    conn.commit()
    conn.close()
    
    return jsonify(stats)

@app.route('/follow_leetcode', methods=['POST'])
@login_required
def follow_leetcode():
    leetcode_username = request.form.get('leetcode_username')
    if not leetcode_username:
        return jsonify({'error': 'No username provided'}), 400
    
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('INSERT INTO followed_leetcode (user_id, leetcode_username) VALUES (?, ?)',
                  (current_user.id, leetcode_username))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Already following this user'}), 400

@app.route('/unfollow_leetcode', methods=['POST'])
@login_required
def unfollow_leetcode():
    leetcode_username = request.form.get('leetcode_username')
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM followed_leetcode WHERE user_id = ? AND leetcode_username = ?',
              (current_user.id, leetcode_username))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/following')
@login_required
def followed_users():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT leetcode_username FROM followed_leetcode WHERE user_id = ?', (current_user.id,))
    followed_usernames = [row['leetcode_username'] for row in c.fetchall()]
    conn.close()
    
    followed_stats = []
    for username in followed_usernames:
        stats = get_leetcode_stats(username)
        if stats:
            followed_stats.append(stats)
    
    return render_template('followed_users.html', followed_stats=followed_stats)



