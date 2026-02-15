import sqlite3
import hashlib
from datetime import datetime
from database import get_connection

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, email, password):
    if not username or not email or not password:
        return False, "All fields are required."

    password_hash = hash_password(password)
    created_at = datetime.now().isoformat()

    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO users (username, email, password_hash, created_at)
        VALUES (?, ?, ?, ?)
        """, (username, email, password_hash, created_at))

        conn.commit()
        conn.close()

        return True, "User registered successfully."

    except sqlite3.IntegrityError:
        return False, "Username or email already exists."

def login_user(username, password):
    password_hash = hash_password(password)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT * FROM users WHERE username = ? AND password_hash = ?
    """, (username, password_hash))

    user = cursor.fetchone()
    conn.close()

    if user:
        return True, user
    else:
        return False, "Invalid credentials."
