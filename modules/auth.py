from flask import Blueprint, request, jsonify
import datetime, jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app

# Imports
from db import get_db_connection
from middleware import token_required

API_VER = '/api/v1'
auth_bp = Blueprint('auth', __name__)

@auth_bp.route(f'{API_VER}/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('name')
        password = data.get('password')

        if not username or not password:
            return jsonify({'message': 'Username and password required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM auth WHERE name = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            token = jwt.encode({
                'user_id': user['id'],
                'role': user['role'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
            }, current_app.config['SECRET_KEY'], algorithm="HS256")

            return jsonify({'token': token, 'message': 'Login successful'})

        return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        # Catch any other general exception
        print(f"An unexpected error occurred: {e}")

# ===========================
#      CRUD OPERATIONS
# ===========================

from werkzeug.security import generate_password_hash

@auth_bp.route(f'{API_VER}/auth/reset-admin-password', methods=['PUT'])
def reset_admin_password():
    # New password to set
    new_password = '1234'
    hashed_password = generate_password_hash(new_password)

    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection failed'}), 500

    cursor = conn.cursor()

    try:
        # Update password only for admin users
        query = "UPDATE auth SET password = %s WHERE role = 'admin'"
        cursor.execute(query, (hashed_password,))
        conn.commit()

        return jsonify({'message': 'Admin password reset to 1234 successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()




# 1. READ (Protected)
@auth_bp.route(f'{API_VER}/auth/users', methods=['GET'])
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
@auth_bp.route(f'{API_VER}/auth/register', methods=['POST'])
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
@auth_bp.route(f'{API_VER}/auth/update/<int:id>', methods=['PUT'])
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
@auth_bp.route(f'{API_VER}/auth/delete/<int:id>', methods=['DELETE'])
@token_required
def delete_user(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM auth WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'User deleted'}), 200



