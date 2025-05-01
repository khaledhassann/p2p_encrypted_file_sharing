# peer/crypto_utils.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import KEY_FILE

# 1. Load (or generate) a 32-byte key
def load_key():
    """Load or generate encryption key"""
    try:
        with open(KEY_FILE, "rb") as f:
            return f.read()
    except FileNotFoundError:
        # Generate new key
        key = os.urandom(32)
        # Ensure directory exists
        os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
        # Save key
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

# 2. Encrypt data
def encrypt(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce  = os.urandom(12)  # 96-bit
    ct     = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct        # prefix nonce

# 3. Decrypt data
def decrypt(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce  = data[:12]
    ct     = data[12:]
    return aesgcm.decrypt(nonce, ct, None)
