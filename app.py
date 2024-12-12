import logging
import time
from flask import Flask, request, jsonify, session
from flasgger import Swagger
from flasgger.utils import swag_from
from config import Config
from models import init_db, register_user, get_user_by_id, get_all_users, update_user_in_db, delete_user_from_db, get_user_by_email
from werkzeug.exceptions import abort
import jwt
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

CORS(app)
app.config['Access-Control-Allow-Origin'] = '*'
app.config["Access-Control-Allow-Headers"] = "Content-Type"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
app.secret_key = os.getenv("SECRET_KEY")
algorithm = os.getenv("ALGORITHM", "HS256")

# Initialize the database
init_db(app)

# Initialize Swagger
swagger = Swagger(app)

# JWT Functions


def generate_jwt(payload):
    """Generate a JWT token."""
    return jwt.encode(payload, app.secret_key)


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
    app.run(port=8003, host="0.0.0.0", debug=True)
