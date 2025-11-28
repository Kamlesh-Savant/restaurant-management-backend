import os
from flask import Flask, jsonify
from dotenv import load_dotenv

def create_app():
    load_dotenv()
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

    # Import blueprints here to avoid circular import
    from modules.auth import auth_bp
    app.register_blueprint(auth_bp)

    return app

app = create_app()

@app.route('/', methods=["GET"])
def home():
    return jsonify({"message": "Welcome to Restaurant Management System Application"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
