import logging
import time
import datetime
from flask import Flask, request, jsonify, session
from flasgger import Swagger
from flasgger.utils import swag_from
from config import Config
from models import init_db, register_user, get_user_by_id, get_all_users, update_user_in_db, delete_user_from_db, get_user_by_email
from werkzeug.exceptions import abort
import jwt
from google.auth.transport import requests
from google.oauth2 import id_token
from flask_cors import CORS
import os
from swagger_definitions import (
    user_registration,
    jwt_generation,
    logout_response,
    token_verification,
    user_list_response,
    user_retrieval,
    user_update,
    user_deletion
)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)


CORS(app, resources={r"/*": {"origins": os.getenv("FRONTEND_URL")}})

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
app.secret_key = os.getenv("JWT_SECRET_KEY")
algorithm = os.getenv("ALGORITHM", "HS256")

# Initialize the database
init_db(app)

# Initialize Swagger
swagger = Swagger(app)

# JWT Functions

# Your Google Client ID here (replace with actual)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

# Endpoint to verify the Google token and generate a JWT
@app.route('/api/generate_jwt', methods=['POST'])
def generate_jwt():
    google_token = request.json.get("googleToken")
    if not google_token:
        return jsonify({"error": "No token provided"}), 400

    try:
        # Verify the token with Google's public keys
        id_info = id_token.verify_oauth2_token(google_token, requests.Request(), GOOGLE_CLIENT_ID)
        user_email = id_info.get("email")

        # Create a JWT token for your app
        payload = {
            "email": user_email,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        jwt_token = jwt.encode(payload, app.secret_key, algorithm)

        return jsonify({"jwt": jwt_token}), 200
    except ValueError as e:
        return jsonify({"error": "Invalid token"}), 401

def decode_jwt(jwt_token):
    """Decode a JWT token."""
    try:
        return jwt.decode(jwt_token, app.secret_key)
    except jwt.ExpiredSignatureError:
        abort(401, "Token has expired")
    except jwt.InvalidTokenError:
        abort(401, "Invalid token")

# Authorization Middleware


def login_required(function):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            abort(401, "Missing or invalid Authorization header")
        token = auth_header.split("Bearer ")[1]
        try:
            decoded_token = decode_jwt(token)
            request.user = decoded_token
        except Exception as e:
            abort(401, str(e))
        return function(*args, **kwargs)
    return wrapper

# Routes


@swag_from(user_registration)
@app.route('/api/users/register', methods=['POST'])
def register_user_endpoint():
    """Register or get existing user."""
    data = request.json
    email = data.get("email")
    name = data.get("name", "Anonymous")

    user = get_user_by_email(email)
    if user is None:
        user = register_user(name, email, data.get("auth_provider", "DEFAULT"))
    return jsonify(user), 200


@swag_from(jwt_generation)
@app.route('/api/generate_jwt', methods=['POST'])
def generate_jwt_endpoint():
    """Generate JWT for a given user."""
    user = request.json
    token = generate_jwt(user)
    return jsonify({"jwt": token}), 200


@swag_from(logout_response)
@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"}), 202


@swag_from(token_verification)
@app.route('/api/verify_token', methods=['GET'])
def verify_token():
    """Verify the Authorization token."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Invalid or missing token"}), 401

    token = auth_header.split("Bearer ")[1]
    try:
        decoded_token = decode_jwt(token)
        return jsonify({"user_id": decoded_token.get("user_id"), "valid": True}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


@swag_from(user_list_response)
@app.route('/api/users', methods=['GET'], endpoint='get_users')
def get_users():
    users = get_all_users()
    return jsonify(users), 200


@swag_from(user_retrieval)
@app.route('/api/users/<int:user_id>', methods=['GET'], endpoint='get_user')
def get_user(user_id):
    user = get_user_by_id(user_id)
    if not user:
        abort(404, "User not found")
    return jsonify(user), 200


@swag_from(user_update)
@app.route('/api/users/<int:user_id>', methods=['PUT'], endpoint='update_user')
def update_user(user_id):
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    if not username and not email:
        return jsonify({'message': 'No data provided to update'}), 400

    result = update_user_in_db(user_id, username, email)
    if 'error' in result:
        return jsonify(result), 400

    return jsonify({'message': 'User updated successfully!'}), 200


@swag_from(user_deletion)
@app.route('/api/users/<int:user_id>', methods=['DELETE'], endpoint='delete_user')
def delete_user(user_id):
    result = delete_user_from_db(user_id)
    if 'error' in result:
        return jsonify(result), 400

    return jsonify({'message': 'User deleted successfully!'}), 200

# Logging Middleware


@app.before_request
def log_request_info():
    logger.info(f"Request: {request.method} {request.url}")
    request.start_time = time.time()


@app.after_request
def log_response_info(response):
    process_time = time.time() - request.start_time
    logger.info(
        f"Response status: {response.status_code} | Time: {process_time:.4f}s")
    return response


if __name__ == '__main__':
    app.run(port=5002, host="0.0.0.0", debug=True)
