# peer/server.py

import os
import socket
import threading
from config import RENDEZVOUS_PORT, SHARED_DIR, KEY_FILE
from peer.auth import (
    load_user_data, save_user_data,
    hash_password, verify_password,
    create_session_token, is_session_valid, renew_session
)
from peer.crypto_utils import decrypt, load_key

# Add this line after imports to load the key once
KEY = load_key()

from peer.file_ops import list_shared_files, send_encrypted_file, receive_encrypted_file

def handle_incoming_peer(conn, addr):
    try:
        data = conn.recv(1024)
        if not data:
            return
            
        # Add PING handling before other commands
        if data == b"PING":
            conn.sendall(b"PONG")
            return
            
        # Convert to string for other commands
        data = data.decode().strip()

        # Check for existing session token
        parts = data.split(maxsplit=1)
        if len(parts[0]) == 32 and is_session_valid(parts[0]):
            token     = parts[0]
            command   = parts[1] if len(parts) > 1 else ""
            authenticated = True
            renew_session(token)
        else:
            command       = data
            authenticated = False

        users = load_user_data()

        if command.startswith("REGISTER"):
            _, username, password = command.split(maxsplit=2)
            if username in users:
                conn.sendall(b"ERROR: Username already exists")
            else:
                pwd_hash, salt = hash_password(password)
                users[username] = {"password_hash": pwd_hash, "salt": salt}
                save_user_data(users)
                conn.sendall(b"OK: Registration successful")

        elif command.startswith("LOGIN"):
            _, username, password = command.split(maxsplit=2)
            if username not in users:
                conn.sendall(b"ERROR: User not found")
            else:
                udata = users[username]
                if verify_password(udata["password_hash"], udata["salt"], password):
                    token = create_session_token(username)
                    conn.sendall(f"OK: {token}".encode())
                else:
                    conn.sendall(b"ERROR: Invalid password")

        elif command == "LIST_FILES":
            if not authenticated:
                conn.sendall(b"ERROR: Authentication required")
            else:
                files = list_shared_files()
                conn.sendall("\n".join(files).encode())

        elif command.startswith("DOWNLOAD"):
            if not authenticated:
                conn.sendall(b"ERROR: Authentication required")
            else:
                _, filename = command.split(maxsplit=1)
                send_encrypted_file(conn, filename)

        elif command.startswith("UPLOAD"):
            if not authenticated:
                conn.sendall(b"ERROR: Authentication required")
            else:
                _, filename = command.split(maxsplit=1)
                if not filename.isprintable() or "/" in filename or "\\" in filename:
                    conn.sendall(b"ERROR: Invalid filename")
                else:
                    try:
                        # Signal ready to receive
                        conn.sendall(b"READY")
                        
                        # Read length header
                        header = b""
                        while not header.endswith(b"\n"):
                            header += conn.recv(1)
                        total_len = int(header.decode().strip())
                        
                        # Read exact number of bytes
                        ciphertext = b""
                        while len(ciphertext) < total_len:
                            chunk = conn.recv(min(4096, total_len - len(ciphertext)))
                            if not chunk:
                                raise ConnectionError("Connection closed during upload")
                            ciphertext += chunk
                        
                        # Decrypt and save
                        plaintext = decrypt(ciphertext, KEY)
                        out_path = os.path.join(SHARED_DIR, filename)
                        with open(out_path, "wb") as f:
                            f.write(plaintext)
                        
                        print(f"[+] Received file '{filename}' from {addr}")
                        conn.sendall(b"OK: File uploaded successfully")
                    
                    except Exception as e:
                        print(f"[-] Upload error: {e}")
                        conn.sendall(f"ERROR: Upload failed - {str(e)}".encode())

        else:
            conn.sendall(b"ERROR: Unknown command")

    except Exception as e:
        print(f"[!] Error in peer handler: {e}")
    finally:
        conn.close()

def start_peer_server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", port))
        s.listen()
        print(f"[*] Peer server listening on port {port}...")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_incoming_peer, args=(conn, addr), daemon=True).start()
