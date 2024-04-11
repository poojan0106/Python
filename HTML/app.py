import secrets
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, redirect, render_template, request, jsonify, session, url_for, flash, current_app
import os
import sqlite3
import smtplib
from email.mime.text import MIMEText
import random
import string
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)

# Configuration
app.config['UPLOAD_FOLDER'] = 'C:\\Users\\pooja\\OneDrive\\Desktop\\helo'  # Update with your upload folder path
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Allowed file extensions

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model example
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

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
        reset_token TEXT,
        reset_token_timestamp TEXT
    );
    ''')
    
    print("Table updated successfully")
    conn.close()
    
logged_in_users = set()

init_db()

def delete_user(email):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    
    cur.execute("DELETE FROM users WHERE email=?", (email,))
    
    conn.commit()
    conn.close()

@app.route('/delete_user', methods=['GET', 'POST'])
def delete_user_route():
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            return render_template('deleteuser.html', error='Email is required')
        
        try:
            delete_user(email)
            return jsonify(success=f'User with email {email} deleted successfully')
        except Exception as e:
            return render_template('deleteuser.html', error=str(e))

    return render_template('deleteuser.html')

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
    cur.execute("UPDATE users SET reset_token=?, reset_token_timestamp=? WHERE email=?", (token, datetime.now(), email))
    conn.commit()
    conn.close()

def send_reset_email(email, token):
    if email:
        msg = MIMEText(f"Click the following link to reset your password: http://localhost:5000/reset-password/{token}")
        msg['Subject'] = 'Password Reset'
        msg['From'] = 'poojangabani12@gmail.com'
        msg['To'] = email

        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login('poojangabani12@gmail.com', 'ifiicmbdwvpfmdso')
            server.sendmail('poojangabani12@gmail.com', email, msg.as_string())
            server.quit()
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        print("Email not found")
        
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

    return render_template('file-upload.html')

@app.route('/file-uploder')
def file_uploder():
    return render_template('file-upload.html')
        
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not first_name or not last_name or not email or not phone or not password or not confirm_password:
            return jsonify(error='All fields are required!')
        
        if get_user(email):
            return jsonify(error='Email is already in use!')

        if password != confirm_password:
            return jsonify(error='Passwords do not match!')

        verification_token = ''.join(random.choices(string.digits, k=6))
        send_verification_email(email, verification_token)
        
        # Store verification token and timestamp in session
        session['verification_token'] = verification_token
        session['verification_token_timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        session['user_data'] = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'phone': phone,
            'password': password
        }

        return jsonify(verification_code=verification_token, email=email)

    return render_template('registration.html')

@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    email = data.get('email')
    code = data.get('code')

    stored_verification_token = session.get('verification_token')
    stored_verification_token_timestamp = session.get('verification_token_timestamp')
    user_data = session.get('user_data')

    if not user_data:
        return jsonify(success=False, error='User data not found. Please try registering again.')

    if stored_verification_token == code:
        # Check if the verification token has expired (e.g., 5 minutes)
        token_timestamp = datetime.strptime(stored_verification_token_timestamp, '%Y-%m-%d %H:%M:%S')
        if datetime.now() - token_timestamp > timedelta(minutes=1):
            return jsonify(success=False, error='Verification code has expired. Please try again.')

        insert_user(user_data['first_name'], user_data['last_name'], user_data['email'], user_data['phone'], user_data['password'])

        # Clear session data
        session.pop('verification_token', None)
        session.pop('verification_token_timestamp', None)
        session.pop('user_data', None)

        return jsonify(success=True, message='Verification successful')
    else:
        return jsonify(success=False, error='Invalid verification code.')


@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    data = request.json
    email = data.get('email')
    
    # Generate a new verification token
    new_verification_token = ''.join(random.choices(string.digits, k=6))
    send_verification_email(email, new_verification_token)
    
    # Store new verification token and timestamp in session
    session['verification_token'] = new_verification_token
    session['verification_token_timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return jsonify(success=True, message='Verification code has been resent.')

def send_verification_email(email, verification_token):
    msg = MIMEText(f'Your verification code is: {verification_token}')
    msg['Subject'] = 'Email Verification'
    msg['From'] = 'poojan@resonantcloud.info'
    msg['To'] = email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login('poojan@resonantcloud.info', 'uelnxuevddwrxbdu')
        server.sendmail('poojan@resonantcloud.info', email, msg.as_string())
        server.quit()
        print("Email Sent successfully")
    except Exception as e:
        print(f"An error occurred: {e}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = get_user(email)
        if user and check_password_hash(user[5], password):  # assuming password is the 6th column in the table
            session['email'] = email
            user_obj = User(user[0])
            session['username'] = email
            logged_in_users.add(email)
            resp = jsonify({"success": "Logged in"})
            resp.set_cookie('username', email)
            
            login_user(user_obj)
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
            token_timestamp = datetime.strptime(user[0][7], '%Y-%m-%d %H:%M:%S.%f')
            if datetime.now() - token_timestamp > timedelta(minutes=5):
                return jsonify(error='Token has expired. Please try again and generate new reset password link.')
            
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
    
@app.route('/logout')
@login_required
def logout():
    
    logout_user()
    if 'username' in session:
        logged_in_users.remove(session['username'])
        session.pop('email', None)
        session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/innerPage')
@login_required
def innerPage():
    return render_template('inner-page.html')


@app.route('/upload', methods=['GET'])
def check_login():
    if 'email' not in session or session['email'] not in logged_in_users:
        return jsonify({"error": "User not logged in"}), 401
    return jsonify({"success": "Logged in"}), 200

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    try:
        file.save(filepath)
        return jsonify({"success": "File uploaded successfully", "filename": file.filename}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
