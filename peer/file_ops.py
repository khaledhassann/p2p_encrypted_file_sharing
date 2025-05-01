# peer/file_ops.py

import os
from peer.crypto_utils import load_key, encrypt, decrypt
from config import SHARED_DIR, RECEIVED_DIR

key = load_key()

def list_shared_files():
    """Return a list of filenames in the shared directory."""
    return os.listdir(SHARED_DIR)

def send_encrypted_file(conn, filename):
    """Send an encrypted file over a socket connection"""
    path = os.path.join(SHARED_DIR, filename)
    try:
        with open(path, "rb") as f:
            plaintext = f.read()
        
        # Encrypt the file contents
        ciphertext = encrypt(plaintext, key)
        
        # Send length as header
        length_header = f"{len(ciphertext)}\n".encode()
        conn.sendall(length_header)
        
        # Send encrypted data in chunks
        chunk_size = 8192  # Larger chunk size
        sent = 0
        while sent < len(ciphertext):
            chunk = ciphertext[sent:sent + chunk_size]
            conn.sendall(chunk)
            sent += len(chunk)
            
        return True
    except Exception as e:
        print(f"[-] Error sending file: {e}")
        return False

def receive_encrypted_file(conn, filename):
    # 1) read the length header
    header = b""
    while not header.endswith(b"\n"):
        header += conn.recv(1)
    total = int(header.decode().strip())

    # 2) read exactly that many bytes
    data = b""
    while len(data) < total:
        data += conn.recv(total - len(data))

    # 3) decrypt and write
    plaintext = decrypt(data, key)
    out = os.path.join(RECEIVED_DIR, filename)
    with open(out, "wb") as f:
        f.write(plaintext)
