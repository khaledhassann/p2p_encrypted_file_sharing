# peer/auth.py

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from config import USER_DATA_FILE, SESSION_TIMEOUT
from argon2 import PasswordHasher, exceptions
from argon2.low_level import hash_secret_raw, Type

# Create a hasher instance with parameters you choose
_ph = PasswordHasher(
    time_cost=2,        # number of iterations
    memory_cost=102400, # in KiB; e.g. 100 MiB
    parallelism=8,
    hash_len=32,
    salt_len=16
)


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

def hash_password(password: str):
    """
    Uses argon2-cffi PasswordHasher to create a salted hash.
    Returns (hash, salt).
    """
    # PasswordHasher generates its own random salt internally
    hash_str = _ph.hash(password)
    # Extract the salt from the encoded hash if you need it:
    # but PasswordHasher encodes everything in `hash_str`.
    return hash_str

def verify_password(stored_hash: str, password: str) -> bool:
    """
    Verifies `password` against the stored Argon2 hash string.
    """
    try:
        return _ph.verify(stored_hash, password)
    except exceptions.VerifyMismatchError:
        return False


# def hash_password(password, salt=None):
#     if salt is None:
#         salt = secrets.token_hex(16)
#     digest = hashlib.sha256((password + salt).encode()).hexdigest()
#     return digest, salt

# def verify_password(stored_hash, salt, input_password):
#     test_hash = hashlib.sha256((input_password + salt).encode()).hexdigest()
#     return test_hash == stored_hash

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
