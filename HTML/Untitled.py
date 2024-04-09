@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        # terms_agreed = request.form.get('terms_agreed')

        # Check if all fields are provided
        if not first_name or not last_name or not email or not phone or not password or not confirm_password:
            return render_template('registration.html', error='All fields are required!')

        # Check if the email already exists
        if email in users:
            return render_template('registration.html', error='Email already registered!')

        # Check if passwords match
        if password != confirm_password:
            return render_template('registration.html', error='Passwords do not match!')

        # Check if terms are agreed
        # if not terms_agreed:
        #     return render_template('registration.html', error='Please agree to the terms and conditions!')

        # If everything is fine, store the user data and redirect to login
        users[email] = {
            'first_name': first_name,
            'last_name': last_name,
            'phone': phone,
            'password': password  # Note: For security reasons, passwords should be hashed before storing
        }
        return redirect(url_for('login'))

    # If it's a GET request, simply render the registration page
    return render_template('registration.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if email and password are provided
        if not email or not password:
            return render_template('login.html', error='Both email and password are required!')

        # Check if the email exists in the user dictionary
        if email not in users:
            return render_template('login.html', error='Email not registered!')

        # Check if the password matches
        if users[email] != password:
            return render_template('login.html', error='Incorrect password!')

        # If everything is fine, set the session and redirect to dashboard
        session['email'] = email
        return redirect(url_for('dashboard'))

    # If it's a GET request, simply render the login page
    return render_template('login.html')