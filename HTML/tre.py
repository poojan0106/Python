import secrets
from flask import Flask, redirect, render_template, request, jsonify, session, url_for
import os
import sqlite3
import smtplib
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)

def init_db():
    conn = sqlite3.connect('database.db')
    print("Opened database successfully")

    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT NOT NULL,
        password TEXT NOT NULL,
        reset_token TEXT
    );
    ''')
    
    print("Table updated successfully")
    conn.close()
    
init_db()

def insert_user(first_name, last_name, email, phone, password):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("INSERT INTO users (first_name, last_name, email, phone, password) VALUES (?, ?, ?, ?, ?)",
                (first_name, last_name, email, phone, generate_password_hash(password)))
    conn.commit()
    conn.close()


def get_user(email):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    conn.close()
    return user

def get_all_users():
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    conn.close()
    return users

@app.route('/users')
def users():
    users = get_all_users()
    return render_template('user.html', users=users)

def update_reset_token(email, token):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("UPDATE users SET reset_token=? WHERE email=?", (token, email))
    conn.commit()
    conn.close()

def send_reset_email(email, token):
    msg = MIMEText(f"Click the following link to reset your password: http://localhost:5000/reset-password/{token}")
    msg['Subject'] = 'Password Reset'
    msg['From'] = 'poojangabani12@gmail.com'  # Update with your email address
    msg['To'] = email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()

        server.login('poojangabani12@gmail.com', 'ifiicmbdwvpfmdso')  # Update with your email and password
        server.sendmail('poojangabani12@gmail.com', email, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"An error occurred: {e}")


@app.route('/')
def index():
    return render_template('index.html')
 
@app.route('/validate', methods=['POST'])
def validate_email():
    if request.method == 'POST':
        email = request.form['email']
        if get_user(email):
            session['email'] = email
            return jsonify(success="email validation  successful")
        else:
            return jsonify(error="Invalid email")

    return render_template('index.html')

@app.route('/blog')
def blog_page():
    if 'email' in session:
        return render_template('blog.html')
    else:
        return redirect(url_for('index'))
        
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not first_name or not last_name or not email or not phone or not password or not confirm_password:
            return jsonify(error='All fields are required!')

        if get_user(email):
            return jsonify(error='Email already registered!')

        if password != confirm_password:
            return jsonify(error='Passwords do not match!')

        insert_user(first_name, last_name, email, phone, password)
        return jsonify(success='Registered successfully')

    return render_template('registration.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = get_user(email)
        if user and check_password_hash(user[5], password):  # assuming password is the 6th column in the table
            session['email'] = email
            return jsonify(success='match credentials')
        else:
            return jsonify(error='Invalid credentials')

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = get_user(email)
        if user:
            token = secrets.token_hex(16)
            update_reset_token(email, token)
            send_reset_email(email, token)
            return jsonify(success='Password reset link sent to your email.')
        else:
            return jsonify(error='Email not found.')

    return render_template('forgot-password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    users = get_all_users()
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            return jsonify(error='Passwords do not match.')
        
        user = [x for x in users if x[6] == token]  # assuming reset_token is the 7th column
        if user:
            update_user_password(user[0][3], password)
            return jsonify(success='Password reset successfully.')
        else:
            return jsonify(error='Invalid or expired token.')

    return render_template('reset-password.html', token=token)  # Pass token to the template

def update_user_password(email, new_password):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    hashed_password = generate_password_hash(new_password)
    cur.execute("UPDATE users SET password=? WHERE email=?", (hashed_password, email))
    conn.commit()
    conn.close()

@app.route('/innerPage')
def innerPage():
    if 'email' in session:
        return render_template('index.html')
    else:
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
