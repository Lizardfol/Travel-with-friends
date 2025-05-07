from flask import Flask, jsonify, request
import psycopg2
from psycopg2 import sql
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Database configuration
def get_db_connection():
    return psycopg2.connect(
        host=os.getenv('DB_HOST'),
        database=os.getenv('DB_NAME'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        port=os.getenv('DB_PORT')
    )



# JWT configuration
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET')

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
            
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user_id']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'])
    
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("""
                        INSERT INTO users (name, email, password_hash, is_guest) 
                        VALUES (%s, %s, %s, %s)
                        RETURNING id, name, email, is_guest
                    """),
                    (data['name'], data['email'], hashed_password, False)
                )
                user = cur.fetchone()
                conn.commit()
                
                token = jwt.encode({
                    'user_id': user[0],
                    'exp': datetime.utcnow() + timedelta(days=1)
                }, app.config['SECRET_KEY'])
                
                return jsonify({
                    'user': {
                        'id': user[0],
                        'name': user[1],
                        'email': user[2],
                        'is_guest': user[3]
                    },
                    'token': token
                }), 201
                
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("SELECT * FROM users WHERE email = %s"),
                    (data['email'],)
                )
                user = cur.fetchone()
                
                if user and check_password_hash(user[3], data['password']):
                    token = jwt.encode({
                        'user_id': user[0],
                        'exp': datetime.utcnow() + timedelta(days=1)
                    }, app.config['SECRET_KEY'])
                    
                    return jsonify({
                        'user': {
                            'id': user[0],
                            'name': user[1],
                            'email': user[2],
                            'is_guest': user[4]
                        },
                        'token': token
                    }), 200
                    
                return jsonify({'message': 'Invalid credentials'}), 401
                
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/journeys', methods=['GET'])
@token_required
def get_journeys(current_user):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("""
                        SELECT * FROM journeys 
                        WHERE user_id = %s
                    """),
                    (current_user,)
                )
                journeys = cur.fetchall()
                
                return jsonify([{
                    'id': j[0],
                    'name': j[2],
                    'description': j[3],
                    'start_date': j[4].isoformat(),
                    'end_date': j[5].isoformat(),
                    'is_public': j[6],
                    'stops': j[7],
                    'companions': j[8],
                    'budget': j[9]
                } for j in journeys]), 200
                
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
