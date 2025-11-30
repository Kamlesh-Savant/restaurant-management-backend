from functools import wraps
from flask import request, jsonify, current_app
import jwt

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Extract Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'success': False, 'message': 'Token missing!'}), 401

        try:
            # Decode token
            decoded = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])

            # Save token data for next routes
            # decoded = {'user_id': 1, 'role': 'admin', 'exp': ...}
            request.user = decoded

        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token!'}), 401
        except Exception as e:
            return jsonify({'success': False, 'message': f'Token error: {str(e)}'}), 401

        return f(*args, **kwargs)

    return decorated
