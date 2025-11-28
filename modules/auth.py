from flask import request, jsonify
import datetime
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

# Imports from other files
from app import app
from db import get_db_connection
from middleware import token_required

# ===========================
#       LOGIN ROUTE
# ===========================
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # We use 'name' as username based on your table, or you can use 'mobile'
    username = data.get('name') 
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Check if user exists
    cursor.execute("SELECT * FROM auth WHERE name = %s", (username,))
    user = cursor.fetchone()
    
    cursor.close()
    conn.close()

    if user:
        # Check password hash
        if check_password_hash(user['password'], password):
            # Generate JWT Token
            token = jwt.encode({
                'user_id': user['id'],
                'role': user['role'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24) # Expires in 24 hours
            }, app.config['SECRET_KEY'], algorithm="HS256")

            return jsonify({'token': token, 'message': 'Login successful'})

    return jsonify({'message': 'Invalid credentials'}), 401


# ===========================
#      CRUD OPERATIONS
# ===========================

# 1. READ (Protected)
@app.route('/auth/users', methods=['GET'])
@token_required
def get_all_users():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, role, mobile, status, created FROM auth")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(users), 200

# 2. CREATE (Public - usually Registration)
@app.route('/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    name = data.get('name')
    password = data.get('password')
    role = data.get('role', 'user')
    mobile = data.get('mobile', '')

    if not name or not password:
        return jsonify({'message': 'Name and Password required'}), 400

    # Secure the password
    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        query = "INSERT INTO auth (name, role, password, mobile) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (name, role, hashed_password, mobile))
        conn.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# 3. UPDATE (Protected)
@app.route('/auth/update/<int:id>', methods=['PUT'])
@token_required
def update_user(id):
    data = request.get_json()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Dynamic Update
    fields = []
    values = []
    
    if 'name' in data:
        fields.append("name = %s")
        values.append(data['name'])
    if 'mobile' in data:
        fields.append("mobile = %s")
        values.append(data['mobile'])
    
    if not fields:
        return jsonify({'message': 'No data to update'}), 400
        
    values.append(id)
    query = f"UPDATE auth SET {', '.join(fields)} WHERE id = %s"

    try:
        cursor.execute(query, tuple(values))
        conn.commit()
        return jsonify({'message': 'User updated'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# 4. DELETE (Protected)
@app.route('/auth/delete/<int:id>', methods=['DELETE'])
@token_required
def delete_user(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM auth WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'User deleted'}), 200