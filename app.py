from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from config import Config
from models import init_db, register_user, login_user, get_user_by_id

app = Flask(__name__)
app.config.from_object(Config)

# Initialize the database
init_db(app)

# Initialize JWT Manager
jwt = JWTManager(app)

# Registration Route


@app.get('/')
def hello_world():
    return f"Hello World!"


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Missing data'}), 400

    # Call the register_user function from models.py
    result = register_user(username, email, password)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result), 201

# Login Route


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Missing email or password'}), 400

    # Call the login_user function from models.py
    result = login_user(email, password)
    if 'error' in result:
        return jsonify(result), 401

    # If login is successful, generate a JWT token
    access_token = create_access_token(identity=result['username'])
    return jsonify({'access_token': access_token}), 200

# Token Verification Route


@app.route('/verify_token', methods=['GET'])
@jwt_required()
def verify_token():
    # Get the username (identity) from the JWT token
    current_user = get_jwt_identity()
    user = get_user_by_id(current_user)
    return jsonify({'user': user}), 200


if __name__ == '__main__':
    app.run(port=5002, host="0.0.0.0", debug=True)
