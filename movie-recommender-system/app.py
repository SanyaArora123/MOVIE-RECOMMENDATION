import os
import numpy as np
import sqlite3
import pickle
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database setup
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Get the current directory path
current_dir = os.path.dirname(__file__)

# Define the paths to pickle files relative to the current directory
popular_path = os.path.join(current_dir, 'popular.pkl')
pt_path = os.path.join(current_dir, 'pt.pkl')
movie_path = os.path.join(current_dir, 'books.pkl')
similarity_scores_path = os.path.join(current_dir, 'similarity_scores.pkl')

# Load the pickled data using the relative paths
popular_df = pickle.load(open(popular_path, 'rb'))
pt = pickle.load(open(pt_path, 'rb'))
movies = pickle.load(open(movie_path, 'rb'))
similarity_scores = pickle.load(open(similarity_scores_path, 'rb'))

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html',
                           movie_name=list(popular_df['title'].values),
                           rating=list(popular_df['avg_rating'].values)
                           )

@app.route('/recommend')
def recommend_ui():
    return render_template('recommend.html')

@app.route('/recommend_movies', methods=['POST'])
def recommend_movies():
    user_input = request.form.get('user_input')
    index = np.where(pt.index == user_input)[0][0]
    similar_items = sorted(list(enumerate(similarity_scores[index])), key=lambda x: x[1], reverse=True)[1:5]

    data = []
    for i in similar_items:
        item = []
        temp_df = movies[movies['title'] == pt.index[i[0]]]
        item.extend(list(temp_df.drop_duplicates('title')['title'].values))
       # item.extend(list(temp_df.drop_duplicates('Book-Title')['Book-Author'].values))
        #item.extend(list(temp_df.drop_duplicates('Book-Title')['Image-URL-M'].values))

        data.append(item)

    print(data)

    return render_template('recommend.html', data=data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == 'admin' and password == 'Hello':
            session['username'] = username
            session['is_admin'] = True
            flash('Admin login successful!')
            return redirect(url_for('admin'))
        else:
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()

            if user and check_password_hash(user['password'], password):
                session['username'] = username
                flash('Login successful!')
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists! Please choose a different one.')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'username' not in session:
        flash('Please log in to access this page.')
        return redirect(url_for('login'))

    if session['username'] != 'admin':
        flash('You do not have permission to view this page.')
        return redirect(url_for('index'))

    conn = get_db_connection()
    users = conn.execute('SELECT id, username FROM users').fetchall()
    conn.close()

    return render_template('admin.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)
