from functools import wraps
from flask import request, jsonify
import jwt
from app import app # Circular import to get the secret key

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if Authorization header exists
        if 'Authorization' in request.headers:
            # Format usually: "Bearer <token>"
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token is missing!'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Decode the token using our Secret Key
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            # You can inject the current_user ID into the function if needed
            # current_user_id = data['user_id'] 
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
            
        return f(*args, **kwargs)
    
    return decorated