from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import requests
import json
from datetime import datetime
from supabase import create_client, Client
from dotenv import load_dotenv

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

load_dotenv()  # Load environment variables from .env file

# Now you can access the variables
url = os.environ.get('SUPABASE_URL')
key = os.environ.get('SUPABASE_KEY')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# Modify the database path to work with Vercel
def get_db_path():
    if os.environ.get('VERCEL_ENV') == 'production':
        # Use /tmp directory in Vercel's environment
        return '/tmp/users.db'
    return 'users.db'

# Modify database connection function
def get_db_connection():
    # Use Supabase client instead of SQLite
    if not url or not key:
        raise ValueError("Supabase URL and Key must be set in environment variables.")
    print(url, key)
    supabase: Client = create_client(url, key)
    return supabase

# Modify init_db function
def init_db():
    # Supabase handles table creation, so this may not be necessary
    pass

# Initialize database on startup
init_db()

@login_manager.user_loader
def load_user(user_id):
    supabase = get_db_connection()
    user_data = supabase.table('users').select('*').eq('id', user_id).execute().data
    if user_data:
        user_data = user_data[0]  # Get the first user
        return User(user_data['id'], user_data['username'])
    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        supabase = get_db_connection()
        try:
            supabase.table('users').insert({'username': username, 'password': hashed_password}).execute()
        except Exception as e:
            return "Username already exists!"  # Handle unique constraint error
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        supabase = get_db_connection()
        user_data = supabase.table('users').select('*').eq('username', username).execute().data

        if user_data and check_password_hash(user_data[0]['password'], password):
            user = User(user_data[0]['id'], user_data[0]['username'])
            login_user(user)
            return redirect(url_for('profile'))
        else:
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    supabase = get_db_connection()
    user_data = supabase.table('users').select('leetcode_username').eq('id', current_user.id).execute().data
    leetcode_username = user_data[0]['leetcode_username'] if user_data else None
    
    followed_usernames = supabase.table('followed_leetcode').select('leetcode_username').eq('user_id', current_user.id).execute().data
    followed_usernames = [row['leetcode_username'] for row in followed_usernames]
    
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
    supabase = get_db_connection()
    supabase.table('users').update({'leetcode_username': leetcode_username}).eq('id', current_user.id).execute()
    
    return jsonify(stats)

@app.route('/follow_leetcode', methods=['POST'])
@login_required
def follow_leetcode():
    leetcode_username = request.form.get('leetcode_username')
    if not leetcode_username:
        return jsonify({'error': 'No username provided'}), 400
    
    supabase = get_db_connection()
    try:
        supabase.table('followed_leetcode').insert({'user_id': current_user.id, 'leetcode_username': leetcode_username}).execute()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/unfollow_leetcode', methods=['POST'])
@login_required
def unfollow_leetcode():
    leetcode_username = request.form.get('leetcode_username')
    
    supabase = get_db_connection()
    supabase.table('followed_leetcode').delete().eq('user_id', current_user.id).eq('leetcode_username', leetcode_username).execute()
    return jsonify({'success': True})

@app.route('/following')
@login_required
def followed_users():
    supabase = get_db_connection()
    followed_usernames = supabase.table('followed_leetcode').select('leetcode_username').eq('user_id', current_user.id).execute().data
    followed_usernames = [row['leetcode_username'] for row in followed_usernames]
    
    followed_stats = []
    for username in followed_usernames:
        stats = get_leetcode_stats(username)
        if stats:
            followed_stats.append(stats)
    
    return render_template('followed_users.html', followed_stats=followed_stats)



