# peer/auth.py

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from config import USER_DATA_FILE, SESSION_TIMEOUT

# In‐memory store of session tokens → { username, expiry }
active_sessions = {}

def load_user_data():
    os.makedirs(os.path.dirname(USER_DATA_FILE), exist_ok=True)
    if not os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "w") as f:
            json.dump({}, f)
    with open(USER_DATA_FILE, "r") as f:
        return json.load(f)

def save_user_data(users):
    os.makedirs(os.path.dirname(USER_DATA_FILE), exist_ok=True)
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f, indent=2)

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.sha256((password + salt).encode()).hexdigest()
    return digest, salt

def verify_password(stored_hash, salt, input_password):
    test_hash = hashlib.sha256((input_password + salt).encode()).hexdigest()
    return test_hash == stored_hash

def create_session_token(username):
    token = secrets.token_hex(16)
    expiry = datetime.now() + timedelta(minutes=SESSION_TIMEOUT)
    active_sessions[token] = {"username": username, "expiry": expiry}
    return token

def is_session_valid(token):
    session = active_sessions.get(token)
    if not session:
        return False
    if datetime.now() > session["expiry"]:
        del active_sessions[token]
        return False
    return True

def renew_session(token):
    if token in active_sessions:
        active_sessions[token]["expiry"] = datetime.now() + timedelta(minutes=SESSION_TIMEOUT)
