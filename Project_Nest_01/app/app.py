from flask import Flask, render_template, request, redirect, url_for, flash, session
import pymongo
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your secret key

# MongoDB connection setup
client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client['Projectnest']
users_collection = db['user']

@app.route('/')
def HOME():
    if 'username' in session:
        return render_template('HOME.html', username=session['username'])
    return redirect('/login')

@app.route('/about')
def ABOUT():
    return render_template('ABOUT.html')

@app.route('/images')
def IMAGES():
    return render_template('IMAGES.html')

@app.route('/videos')
def VIDEOS():
    return render_template('VIEDOS.html')

@app.route('/fitness')
def FITTNESS():
    return render_template('FITTNESS.html')

@app.route('/contact')
def CONTACT():
    return render_template('CONTACT.html')

@app.route('/wellness')
def WELLNESS():
    return render_template('WELLNESS.html')

@app.route('/services')
def SERVICES():
    return render_template('SERVICES.html')

@app.route('/signup', methods=['GET', 'POST'])
def SIGNUP():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Hash the password using SHA-256
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Check if the username already exists in the database
        if users_collection.find_one({'username': username}):
            flash('Username already exists', 'error')
            return redirect('/signup')

        # Insert the user data into the database
        user_data = {
            'username': username,
            'email': email,
            'password': hashed_password
        }
        users_collection.insert_one(user_data)

        flash('Account created successfully', 'success')
        return redirect('/login')

    return render_template('SIGNUP.html')

@app.route('/login', methods=['GET', 'POST'])
def LOGIN():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the entered password for comparison
        entered_password_hashed = hashlib.sha256(password.encode()).hexdigest()

        # Check if the username and hashed password match a user in the database
        user = users_collection.find_one({'username': username, 'password': entered_password_hashed})

        if user:
            flash('Login successful', 'success')
            session['username'] = username  # Store the username in the session
            return redirect('/')
        else:
            flash('Login failed. Please check your username and password.', 'error')

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def LOGOUT():
    session.pop('username', None)  # Remove the username from the session
    flash('Logout successful', 'success')
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)