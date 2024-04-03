from flask import Flask, request, jsonify
import pymysql.cursors
import re
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
import bcrypt  # Import bcrypt

app = Flask(__name__)

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "secret_key"  # Change this to a random secret key
jwt = JWTManager(app)

# Database connection info
db_config = {
    "host": "database-1.cfos0cg2kgff.ap-south-1.rds.amazonaws.com",
    "user": "admin",
    "password": "jenishsavaliya",
    "db": "flaskapp",
    "cursorclass": pymysql.cursors.DictCursor  # Return rows as dictionaries
}


def get_db_connection():
    connection = pymysql.connect(**db_config)
    return connection


def is_valid_email(email):
    """Check if the provided email address is valid."""
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None


def check_email_in_db(email):
    """Check if an email exists in the database."""
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Your SQL query to check if the email exists
            query = "SELECT email FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            return bool(result)  # Returns True if the email exists, False otherwise
    finally:
        connection.close()


@app.route('/')
def home():
    return "Welcome"


#resetpassword
@app.route('/resetpassword', methods=['POST'])
@jwt_required()  
def reset_password():
    user_id = get_jwt_identity()  
    data = request.get_json()

    if not data or 'new_password' not in data:
        return jsonify({"message": "New password is required"}), 400

    new_password = data['new_password'].encode('utf-8')  

    hashed_new_password = bcrypt.hashpw(new_password, bcrypt.gensalt())

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Update the user's password in the database
            update_sql = "UPDATE users SET password = %s WHERE id = %s"
            cursor.execute(update_sql, (hashed_new_password, user_id))
            connection.commit()

            return jsonify({"message": "Password reset successfully"}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500
    finally:
        connection.close()


#check email
@app.route('/checkemail', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get('email')
    if not email or not is_valid_email(email):
        return jsonify({"message": "Invalid or missing email"}), 400

    exists = check_email_in_db(email)
    return jsonify({'exists': exists})


#  check password
@app.route('/checkpassword', methods=['POST'])
def check_password():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"message": "Both email and password are required"}), 400

    email = data.get('email')
    password = data.get('password').encode('utf-8')  # Encode the password to bytes

    if not is_valid_email(email):
        return jsonify({"message": "Invalid email format"}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Query the user by email
            cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user:
                # Check if the provided password matches the hashed password
                if bcrypt.checkpw(password, user['password'].encode('utf-8')):
                    return jsonify({"message": "The password is correct"}), 200
                else:
                    return jsonify({"message": "The password is incorrect"}), 401
            else:
                return jsonify({"message": "Email not found"}), 404
    finally:
        connection.close()


# register API
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'name' not in data or 'email' not in data or 'password' not in data:
        return jsonify({"message": "Name, email, and password are required"}), 400

    name = data.get('name')
    email = data.get('email')
    password = data.get('password').encode('utf-8')  # Encode password to bytes

    if not is_valid_email(email):
        return jsonify({"message": "Invalid email format"}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Check if email already exists
            email_check_sql = "SELECT email FROM users WHERE email = %s"
            cursor.execute(email_check_sql, (email,))
            if cursor.fetchone():
                return jsonify({"message": "Email already registered"}), 409

            # Insert new user with hashed password
            insert_sql = "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)"
            cursor.execute(insert_sql, (name, email, hashed_password))
            connection.commit()
            user_id = cursor.lastrowid
            # Create JWT tokens
            access_token = create_access_token(identity=user_id)
            refresh_token = create_refresh_token(identity=user_id)

            return jsonify({
                "message": "User created successfully",
                "user": {
                    "id": user_id,
                    "name": name,
                    "email": email
                },
                "access_token": access_token,
                "refresh_token": refresh_token
            }), 201
    finally:
        connection.close()


# Login API
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"message": "Both email and password are required"}), 400

    email = data.get('email')
    password = data.get('password').encode('utf-8')
    if not is_valid_email(email):
        return jsonify({"message": "Invalid email format"}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            user_check_sql = "SELECT id, name, email, password FROM users WHERE email = %s"
            cursor.execute(user_check_sql, (email,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):  # Verify hashed password
                # Create JWT tokens
                access_token = create_access_token(identity=user['id'])
                refresh_token = create_refresh_token(identity=user['id'])

                return jsonify({
                    "message": "Login successful",
                    "name": user['name'],
                    "email": user['email'],
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }), 200
            else:
                return jsonify({"message": "Incorrect email or password"}), 401
    finally:
        connection.close()


# Update API
@app.route('/update', methods=['POST'])
@jwt_required()  # Require access token for this route
def update_user():
    user_id = get_jwt_identity()  # Get user ID from the access token
    data = request.get_json()

    if not data:
        return jsonify({"message": "No data provided"}), 400

    name = data.get('name')
    email = data.get('email')
    password = data.get('password', '').encode('utf-8')  # Encode password to bytes

    updated_fields = []  # Track which fields are updated

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            updates = []
            params = []

            if name:
                updates.append("name = %s")
                params.append(name)
                updated_fields.append('name')
            if email:
                if not is_valid_email(email):
                    return jsonify({"message": "Invalid email format"}), 400
                updates.append("email = %s")
                params.append(email)
                updated_fields.append('email')
            if password:
                # Hash the new password
                hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
                updates.append("password = %s")
                params.append(hashed_password)
                updated_fields.append('password')

            if updates:
                update_sql = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
                params.append(user_id)
                cursor.execute(update_sql, params)
                connection.commit()

                # Fetch updated user info
                cursor.execute("SELECT name, email FROM users WHERE id = %s", (user_id,))
                updated_user = cursor.fetchone()

                # Create new JWT tokens
                access_token = create_access_token(identity=user_id)
                refresh_token = create_refresh_token(identity=user_id)

                updated_fields_message = ", ".join(updated_fields) + " updated successfully"
                return jsonify({
                    "message": updated_fields_message,
                    "updated_data": updated_user,
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }), 200
            else:
                return jsonify({"message": "No changes made"}), 200
    finally:
        connection.close()


# Refresh API
@app.route('/refreshtoken', methods=['POST'])
@jwt_required(refresh=True)  # Ensure this is a refresh token
def refresh():
    current_user_id = get_jwt_identity()  # Extract user identity from the refresh token
    additional_claims = get_jwt()  # You can include more claims if needed

    # Generate a new access token
    new_access_token = create_access_token(identity=current_user_id, additional_claims=additional_claims)

    # Fetch user details from the database using user_id (except password)
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, name, email FROM users WHERE id = %s", (current_user_id,))
            user = cursor.fetchone()

            if user:
                return jsonify({
                    "message": "New access token created.",
                    "access_token": new_access_token,
                    "user": {
                        "id": user["id"],
                        "name": user["name"],
                        "email": user["email"]
                    }
                }), 200
            else:
                return jsonify({"message": "User not found"}), 404
    finally:
        connection.close()


# Userdetails API
@app.route('/userdetails', methods=['GET'])
@jwt_required()  # Requires an access token
def user_details():
    current_user_id = get_jwt_identity()  # Get the identity of the current user

    # Fetch user details from the database using the user ID
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, name, email FROM users WHERE id = %s", (current_user_id,))
            user = cursor.fetchone()

            if user:
                return jsonify({
                    "message": "User details fetched successfully.",
                    "user": {
                        "id": user["id"],
                        "name": user["name"],
                        "email": user["email"]
                    }
                }), 200
            else:
                return jsonify({"message": "User not found"}), 404
    finally:
        connection.close()


if __name__ == '__main__':
    app.run(debug=True)
