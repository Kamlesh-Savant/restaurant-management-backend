import os
from flask import Flask, jsonify
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

app = Flask(__name__)

# Load Secret Key from .env
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


@app.route('/', methods=["GET"])
def home():
    return jsonify({"Message":"Welcome to Restorunt Management System Application"})

############################################## Import New Modules Here Only ###############################################
# Import modules at the bottom
import modules.auth 



###############################################








if __name__ == '__main__':
    app.run(debug=True, port=5000)