# app.py
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
import pyotp

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username, password=password).first()

    if user:
        session['user_id'] = user.id
        return jsonify({'message': 'Login successful. Please enter OTP.'})

    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/generate_otp', methods=['POST'])
def generate_otp():
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    user = User.query.get(session['user_id'])
    totp = pyotp.TOTP(user.otp_secret)
    otp = totp.now()

    return jsonify({'otp': otp})

@app.route('/validate_otp', methods=['POST'])
def validate_otp():
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    user = User.query.get(session['user_id'])
    data = request.get_json()
    otp = data.get('otp')

    totp = pyotp.TOTP(user.otp_secret)
    if totp.verify(otp):
        return jsonify({'message': 'OTP verification successful. User logged in.'})

    return jsonify({'error': 'Invalid OTP'}), 401

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            print(f"Error creating tables: {e}")

    app.run(debug=True)
