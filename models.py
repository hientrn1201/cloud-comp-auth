from flask_mysqldb import MySQL
import bcrypt

# Initialize MySQL
mysql = None


def init_db(app):
    """
    Initializes the MySQL connection for the app.
    This should be called in app.py to bind the Flask app to MySQL.
    """
    global mysql
    mysql = MySQL(app)

# User Model and Functions


def register_user(username, email, password):
    """
    Registers a new user in the database.

    Args:
    username: The username of the new user.
    email: The email of the new user.
    password: The password of the new user (plain text, to be hashed).

    Returns:
    A dictionary with a success message or an error if the user already exists.
    """
    cur = mysql.connection.cursor()

    # Check if the email or username is already in use
    cur.execute(
        "SELECT * FROM users WHERE email = %s OR username = %s", (email, username))
    existing_user = cur.fetchone()

    if existing_user:
        cur.close()
        return {'error': 'User with this email or username already exists'}

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode(
        'utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Insert new user into the database
    cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password))
    mysql.connection.commit()
    cur.close()

    return {'message': 'User registered successfully!'}


def login_user(email, password):
    """
    Logs in a user by verifying their email and password.

    Args:
    email: The email of the user.
    password: The password of the user (plain text).

    Returns:
    A dictionary with the user's info if successful, or an error message if not.
    """
    cur = mysql.connection.cursor()

    # Fetch the user by email
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return {'error': 'User not found'}

    # Verify the password
    # user[3] is the hashed password
    if not bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
        return {'error': 'Invalid password'}

    # Return the user's info
    return {
        'user_id': user[0],
        'username': user[1],
        'email': user[2],
        'message': 'Login successful'
    }


def get_user_by_id(user_id):
    """
    Fetches a user by their ID.

    Args:
    user_id: The ID of the user.

    Returns:
    The user's information or None if the user is not found.
    """
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return None

    return {
        'user_id': user[0],
        'username': user[1],
        'email': user[2]
    }


def get_all_users():
    """
    Fetches all users from the database.

    Returns:
    A list of dictionaries containing user information.
    """
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    cur.close()

    return [
        {
            'user_id': user[0],
            'username': user[1],
            'email': user[2]
        } for user in users
    ]


def update_user_in_db(user_id, username=None, email=None):
    cur = mysql.connection.cursor()
    updates = []
    params = []

    if username:
        updates.append("username = %s")
        params.append(username)
    if email:
        updates.append("email = %s")
        params.append(email)

    if not updates:
        return {'error': 'No fields to update'}

    params.append(user_id)
    query = f"UPDATE users SET {', '.join(updates)} WHERE user_id = %s"
    cur.execute(query, tuple(params))
    mysql.connection.commit()
    cur.close()

    return {'message': 'User updated successfully!'}


def delete_user_from_db(user_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()

    return {'message': 'User deleted successfully!'}
