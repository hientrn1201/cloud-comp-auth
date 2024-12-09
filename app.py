import logging
import time
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flasgger import Swagger
from flasgger.utils import swag_from
from config import Config
from models import init_db, register_user, login_user, get_user_by_id, get_all_users, update_user_in_db, delete_user_from_db
from google.oauth2 import id_token
from google.auth.transport import requests

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# Initialize the database
init_db(app)

# Initialize JWT Manager
jwt = JWTManager(app)

# Initialize Swagger
swagger = Swagger(app)


@app.route('/api/auth/google', methods=['POST'])
def google_login():
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({'message': 'Token is missing'}), 400

    try:
        # Verify the token with Google
        id_info = id_token.verify_oauth2_token(token, requests.Request(), "366999094984-7hof4rq81g82r0ahn68flnu5odgh85di.apps.googleusercontent.com")

        # Extract user info
        email = id_info.get('email')
        name = id_info.get('name')

        # Create a JWT for the user
        access_token = create_access_token(identity={'email': email, 'name': name})

        return jsonify({'authToken': access_token}), 200

    except ValueError as e:
        # Invalid token
        return jsonify({'message': 'Invalid token'}), 401


# Apply middleware to protected routes
def check_jwt_token():
    """Middleware to check for JWT token in Authorization header."""
    # Skip JWT validation for google_login route
    if request.endpoint == 'google_login':
        return

    # Retrieve token from Authorization header
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Token is missing'}), 403

    # Ensure the token follows the "Bearer <token>" format
    token_parts = token.split()
    if len(token_parts) != 2 or token_parts[0] != "Bearer":
        return jsonify({'message': 'Token is invalid'}), 403

    token = token_parts[1]  # Extract the Bearer token

    try:
        # Decode and validate the JWT token using flask_jwt_extended
        get_jwt_identity()  # Will automatically validate the token
    except Exception as e:
        return jsonify({'message': 'Token is invalid'}), 403



# Logging middleware
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


@app.get('/')
@swag_from({
    "responses": {
        200: {
            "description": "Returns a simple Hello World message."
        }
    }
})
def hello_world():
    return "Hello World!"


@app.route('/api/register', methods=['POST'])
@swag_from({
    "parameters": [
        {
            "name": "body",
            "in": "body",
            "required": True,
            "schema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "email": {"type": "string"},
                    "password": {"type": "string"}
                },
                "required": ["username", "email", "password"]
            }
        }
    ],
    "responses": {
        201: {
            "description": "User registered successfully."
        },
        400: {
            "description": "Missing data or registration error."
        }
    }
})
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Missing data'}), 400

    result = register_user(username, email, password)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result), 201


@app.route('/api/login', methods=['POST'])
@swag_from({
    "parameters": [
        {
            "name": "body",
            "in": "body",
            "required": True,
            "schema": {
                "type": "object",
                "properties": {
                    "email": {"type": "string"},
                    "password": {"type": "string"}
                },
                "required": ["email", "password"]
            }
        }
    ],
    "responses": {
        200: {
            "description": "Login successful, returns access token."
        },
        401: {
            "description": "Invalid credentials."
        }
    }
})
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Missing email or password'}), 400

    result = login_user(email, password)
    if 'error' in result:
        return jsonify(result), 401

    access_token = create_access_token(identity=result['username'])
    return jsonify({'access_token': access_token}), 200


@app.route('/api/verify_token', methods=['GET'])
@jwt_required()
@swag_from({
    "responses": {
        200: {
            "description": "Verifies the JWT token and returns user details."
        },
        401: {
            "description": "Invalid or missing token."
        }
    }
})
def verify_token():
    current_user = get_jwt_identity()
    user = get_user_by_id(current_user)
    return jsonify({'user': user}), 200


@app.route('/api/users', methods=['GET'])
@swag_from({
    "responses": {
        200: {
            "description": "Returns a list of all users."
        }
    }
})
def get_users():
    users = get_all_users()
    return jsonify(users), 200


@app.route('/api/users/<int:user_id>', methods=['GET'])
@swag_from({
    "parameters": [
        {
            "name": "user_id",
            "in": "path",
            "type": "integer",
            "required": True
        }
    ],
    "responses": {
        200: {
            "description": "Returns details of the user."
        },
        404: {
            "description": "User not found."
        }
    }
})
def get_user(user_id):
    user = get_user_by_id(user_id)
    if user is None:
        return jsonify({'message': 'User not found'}), 404
    return jsonify(user), 200


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@swag_from({
    "parameters": [
        {
            "name": "user_id",
            "in": "path",
            "type": "integer",
            "required": True
        },
        {
            "name": "body",
            "in": "body",
            "required": True,
            "schema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "email": {"type": "string"}
                }
            }
        }
    ],
    "responses": {
        200: {
            "description": "User updated successfully."
        },
        400: {
            "description": "No data provided or update error."
        }
    }
})
def update_user(user_id):
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    if not username and not email:
        return jsonify({'message': 'No data provided to update'}), 400

    # Call a function to update the user in the database
    result = update_user_in_db(user_id, username, email)
    if 'error' in result:
        return jsonify(result), 400

    return jsonify({'message': 'User updated successfully!'}), 200


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    result = delete_user_from_db(user_id)
    if 'error' in result:
        return jsonify(result), 400

    return jsonify({'message': 'User deleted successfully!'}), 200


if __name__ == '__main__':
    app.run(port=5002, host="0.0.0.0", debug=True)
