from flask import Flask, render_template, request, redirect
import sqlite3
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

# Database initialization
conn = sqlite3.connect('users.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users
                  (username TEXT, password TEXT, address TEXT, location TEXT)''')
conn.commit()

# Encryption/Decryption functions
def encrypt(text):
    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_text = cipher.encrypt(pad(text.encode(), AES.block_size))
    return cipher_text, key

def decrypt(cipher_text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    text = unpad(cipher.decrypt(cipher_text), AES.block_size)
    return text.decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        address = request.form['address']
        location = request.form['location']

        # Hash and salt the password
        salt = os.urandom(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

        # Encrypt the address and location
        address_encrypted, address_key = encrypt(address)
        location_encrypted, location_key = encrypt(location)

        # Store the user details in the database
        cursor.execute('INSERT INTO users VALUES (?, ?, ?, ?)',
                       (username, password_hash, address_encrypted, location_encrypted))
        conn.commit()

        return redirect('/welcome?username=' + username)

    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Retrieve user details from the database
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        user = cursor.fetchone()

        if user:
            # Verify the password
            stored_password = user[1]
            salt = user[2]
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            if password_hash == stored_password:
                return redirect('/welcome?username=' + username)

        error_message = "Login details incorrect. Please try again."
        return render_template('signin.html', error_message=error_message)

    return render_template('signin.html')

@app.route('/welcome')
def welcome():
    username = request.args.get('username')
    return render_template('welcome.html', username=username)

if __name__ == '__main__':
    app.run()
