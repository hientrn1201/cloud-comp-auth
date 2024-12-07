import logging
import time
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from config import Config
from models import init_db, register_user, login_user, get_user_by_id, get_all_users, update_user_in_db, delete_user_from_db

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# Initialize the database
init_db(app)

# Initialize JWT Manager
jwt = JWTManager(app)

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
def hello_world():
    return "Hello World!"


@app.route('/api/register', methods=['POST'])
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
def verify_token():
    current_user = get_jwt_identity()
    user = get_user_by_id(current_user)
    return jsonify({'user': user}), 200


@app.route('/api/users', methods=['GET'])
def get_users():
    users = get_all_users()
    return jsonify(users), 200


@app.route('/api/user', methods=['GET'])
def get_user():
    # Use query parameter for user_id instead of path parameter
    user_id = request.args.get('user_id', type=int)
    if not user_id:
        return jsonify({'message': 'Missing user_id parameter'}), 400

    user = get_user_by_id(user_id)
    if user is None:
        return jsonify({'message': 'User not found'}), 404
    return jsonify(user), 200


@app.route('/api/users', methods=['PUT'])
def update_user():
    # Use body request for updating user
    data = request.get_json()
    user_id = data.get('user_id')
    username = data.get('username')
    email = data.get('email')

    if not user_id or (not username and not email):
        return jsonify({'message': 'Missing data'}), 400

    result = update_user_in_db(user_id, username, email)
    if 'error' in result:
        return jsonify(result), 400

    return jsonify({'message': 'User updated successfully!'}), 200


@app.route('/api/users', methods=['DELETE'])
def delete_user():
    # Use query parameter for user_id instead of path parameter
    user_id = request.args.get('user_id', type=int)
    if not user_id:
        return jsonify({'message': 'Missing user_id parameter'}), 400

    result = delete_user_from_db(user_id)
    if 'error' in result:
        return jsonify(result), 400

    return jsonify({'message': 'User deleted successfully!'}), 200


if __name__ == '__main__':
    app.run(port=8003, host="0.0.0.0", debug=True)
