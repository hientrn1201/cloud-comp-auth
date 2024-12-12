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
import pathlib

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


@swag_from({
    'responses': {
        200: {
            'description': 'User registered successfully or retrieved existing user',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'User registered successfully!'
                    },
                    'user': {
                        'type': 'object',
                        'properties': {
                            'user_id': {'type': 'integer'},
                            'username': {'type': 'string'},
                            'email': {'type': 'string'}
                        }
                    }
                }
            }
        },
        400: {
            'description': 'Error in registration',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
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


@swag_from({
    'responses': {
        200: {
            'description': 'JWT generated successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'jwt': {'type': 'string'}
                }
            }
        }
    }
})
@app.route('/api/generate_jwt', methods=['POST'])
def generate_jwt_endpoint():
    """Generate JWT for a given user."""
    user = request.json
    token = generate_jwt(user)
    return jsonify({"jwt": token}), 200


@swag_from({
    'responses': {
        202: {
            'description': 'User logged out successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string', 'example': 'Logged out'}
                }
            }
        }
    }
})
@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"}), 202


# @app.route('/api/verify_token', methods=['GET'])
# @login_required
# def verify_token():
#     user_id = request.user.get("user_id")
#     user = get_user_by_id(user_id)
#     if not user:
#         abort(404, "User not found")
#     return jsonify({"user": user}), 200


@swag_from({
    'responses': {
        200: {
            'description': 'List of users retrieved successfully',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'user_id': {'type': 'integer'},
                        'username': {'type': 'string'},
                        'email': {'type': 'string'}
                    }
                }
            }
        }
    }
})
@app.route('/api/users', methods=['GET'], endpoint='get_users')
@login_required
def get_users():
    users = get_all_users()
    return jsonify(users), 200


@swag_from({
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user to retrieve'
        }
    ],
    'responses': {
        200: {
            'description': 'User retrieved successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'user_id': {'type': 'integer'},
                    'username': {'type': 'string'},
                    'email': {'type': 'string'}
                }
            }
        },
        404: {
            'description': 'User not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
@app.route('/api/users/<int:user_id>', methods=['GET'], endpoint='get_user')
@login_required
def get_user(user_id):
    user = get_user_by_id(user_id)
    if not user:
        abort(404, "User not found")
    return jsonify(user), 200


@swag_from({
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user to update'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'email': {'type': 'string'}
                }
            }
        }
    ],
    'responses': {
        200: {
            'description': 'User updated successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        400: {
            'description': 'No data provided to update',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        }
    }
})
@app.route('/api/users/<int:user_id>', methods=['PUT'], endpoint='update_user')
@login_required
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


@swag_from({
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user to delete'
        }
    ],
    'responses': {
        200: {
            'description': 'User deleted successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        400: {
            'description': 'Error deleting user',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
@app.route('/api/users/<int:user_id>', methods=['DELETE'], endpoint='delete_user')
@login_required
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
