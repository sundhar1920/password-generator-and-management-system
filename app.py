from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import string
import random
from cryptography.fernet import Fernet
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Generate encryption key
if not os.path.exists('encryption_key.key'):
    key = Fernet.generate_key()
    with open('encryption_key.key', 'wb') as key_file:
        key_file.write(key)

with open('encryption_key.key', 'rb') as key_file:
    key = key_file.read()
    fernet = Fernet(key)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    passwords = db.relationship('Password', backref='user', lazy=True)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    encrypted_password = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html')

        user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# API Routes
@app.route('/api/generate-password', methods=['POST'])
@login_required
def generate_password():
    data = request.get_json()
    length = data.get('length', 12)
    use_uppercase = data.get('uppercase', True)
    use_lowercase = data.get('lowercase', True)
    use_numbers = data.get('numbers', True)
    use_special = data.get('special', True)

    characters = ''
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_numbers:
        characters += string.digits
    if use_special:
        characters += string.punctuation

    if not characters:
        return jsonify({'error': 'At least one character type must be selected'}), 400

    password = ''.join(random.choice(characters) for _ in range(length))
    return jsonify({'password': password})

@app.route('/api/store-password', methods=['POST'])
@login_required
def store_password():
    data = request.get_json()
    service = data.get('service')
    username = data.get('username')
    password = data.get('password')

    if not all([service, username, password]):
        return jsonify({'success': False, 'error': 'All fields are required'}), 400

    encrypted_password = fernet.encrypt(password.encode()).decode()
    
    password_entry = Password(
        service=service,
        username=username,
        encrypted_password=encrypted_password,
        user_id=current_user.id
    )
    
    db.session.add(password_entry)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/api/get-passwords')
@login_required
def get_passwords():
    passwords = Password.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'passwords': [{
            'id': p.id,
            'service': p.service,
            'username': p.username,
            'created_at': p.created_at.isoformat()
        } for p in passwords]
    })

@app.route('/api/get-password/<int:id>')
@login_required
def get_password(id):
    password = Password.query.filter_by(id=id, user_id=current_user.id).first()
    if not password:
        return jsonify({'error': 'Password not found'}), 404

    decrypted_password = fernet.decrypt(password.encrypted_password.encode()).decode()
    return jsonify({'password': decrypted_password})

@app.route('/api/delete-password/<int:id>', methods=['DELETE'])
@login_required
def delete_password(id):
    password = Password.query.filter_by(id=id, user_id=current_user.id).first()
    if not password:
        return jsonify({'success': False, 'error': 'Password not found'}), 404

    db.session.delete(password)
    db.session.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 