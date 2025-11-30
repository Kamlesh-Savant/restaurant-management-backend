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

        if not data:
            return jsonify({'success':False,'message': 'Invalid request. JSON data is required'}), 400

        username = data.get('name')
        password = data.get('password')

        if not username or not password:
            return jsonify({'success':False,'message': 'Username and password are required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM auth WHERE name = %s", (username,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if not user:
            return jsonify({'success':False,'message': 'User not found. Please register first'}), 404

        if not check_password_hash(user['password'], password):
            return jsonify({'success':False,'message': 'Incorrect password'}), 401

        # JWT Token Creation
        token = jwt.encode({
            'user_id': user['id'],
             'name': user['name'],
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
        }, current_app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({
            'success':True,
            'token': token,
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'name': user['name'],
                'role': user['role']
            }
        }), 200

    except Exception as e:
        print(f"Login Error: {e}")
        return jsonify({'success':False,'message': 'Internal Server Error. Please try again later'}), 500

# ===========================
#      CRUD OPERATIONS
# ===========================



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
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'message': 'Database connection failed'}), 500

        cursor = conn.cursor(dictionary=True)

        # Exclude admin users properly
        query = "SELECT id, name, role, mobile, status, created FROM auth WHERE role != %s"
        cursor.execute(query, ('admin',))

        users = cursor.fetchall()
        return jsonify({
            'message': 'Users fetched successfully',
            'count': len(users),
            'data': users
        }), 200

    except Exception as e:
        print(f"Error fetching users: {e}")
        return jsonify({'message': 'Internal server error while fetching users'}), 500

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass


# 2. CREATE New User (Admin Only)
@auth_bp.route(f'{API_VER}/auth/register', methods=['POST'])
@token_required
def register_user():
    conn = None
    cursor = None
    try:
        # Logged-in user info from token
        current_user = getattr(request, 'user', None)

        # Only admin can create users
        if not current_user or current_user.get('role') != 'admin':
            return jsonify({
                'success': False,
                'message': 'Access denied! Only admin can create users'
            }), 403

        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'message': 'Invalid request. JSON body required'
            }), 400

        name = data.get('name')
        role = data.get('role')  # default role user
        status = data.get('status', 1)  # default role user
        mobile = data.get('mobile', '')

        if not name:
            return jsonify({
                'success': False,
                'message': 'Name field is required'
            }), 400

        # Connect DB
        conn = get_db_connection()
        if not conn:
            return jsonify({
                'success': False,
                'message': 'Database connection failed'
            }), 500

        cursor = conn.cursor()

        # 🔍 Check duplicate name
        cursor.execute("SELECT id FROM auth WHERE name = %s", (name,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({
                'success': False,
                'message': f'User with name {name} already exists'
            }), 409  # 409 Conflict

        # Default password
        default_password = '1234'
        hashed_password = generate_password_hash(default_password)

        # Insert new user
        query = """
            INSERT INTO auth (name, role, password, mobile, status)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (name, role, hashed_password, mobile, status))
        conn.commit()

        return jsonify({
            'success': True,
            'message': f'User {name} created successfully with default password 1234'
        }), 201

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error creating user: {str(e)}'
        }), 500

    finally:
        if cursor: cursor.close()
        if conn: conn.close()



# 3. UPDATE User (Protected)
@auth_bp.route(f'{API_VER}/auth/update/<int:id>', methods=['PUT'])
@token_required
def update_user(id):
    conn = None
    cursor = None
    try:
        # Get logged-in user info
        current_user = getattr(request, 'user', None)

        if not current_user:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401

        # Optionally: allow only admin to update
        # if current_user.get('role') != 'admin':
        #     return jsonify({'success': False, 'message': 'Access denied'}), 403

        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request. JSON body required'}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500

        cursor = conn.cursor()

        fields = []
        values = []

        # Check which fields to update
        if 'name' in data:
            # Check duplicate name
            cursor.execute("SELECT id FROM auth WHERE name = %s AND id != %s", (data['name'], id))
            existing_user = cursor.fetchone()
            if existing_user:
                return jsonify({'success': False, 'message': f'User with name {data["name"]} already exists'}), 409
            fields.append("name = %s")
            values.append(data['name'])

        if 'mobile' in data:
            fields.append("mobile = %s")
            values.append(data['mobile'])

        if 'role' in data:
            fields.append("role = %s")
            values.append(data['role'])

        if 'status' in data:
            fields.append("status = %s")
            values.append(data['status'])

        if not fields:
            return jsonify({'success': False, 'message': 'No valid data to update'}), 400

        values.append(id)
        query = f"UPDATE auth SET {', '.join(fields)} WHERE id = %s"

        cursor.execute(query, tuple(values))
        conn.commit()

        return jsonify({
            'success': True,
            'message': f'User with ID {id} updated successfully'
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error updating user: {str(e)}'}), 500

    finally:
        if cursor: cursor.close()
        if conn: conn.close()



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



