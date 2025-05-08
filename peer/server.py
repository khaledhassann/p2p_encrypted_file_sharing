# peer/server.py

import os
import socket
import threading
from config import SHARED_DIR              # removed RENDEZVOUS_PORT, KEY_FILE
from peer.auth import (
    load_user_data, save_user_data,
    hash_password, verify_password,
    create_session_token, is_session_valid, renew_session
)
from peer.crypto_utils import encrypt, decrypt, load_key

# Load the AES key once
KEY = load_key()

from peer.file_ops import list_shared_files, send_encrypted_file, receive_encrypted_file

def handle_incoming_peer(conn, addr):
    try:
        data = conn.recv(1024)
        if not data:
            return

        # Ping handler
        if data == b"PING":
            conn.sendall(b"PONG")
            return

        # Decode command
        data = data.decode().strip()

        # Check session token
        parts = data.split(maxsplit=1)
        if len(parts[0]) == 32 and is_session_valid(parts[0]):
            token        = parts[0]
            command      = parts[1] if len(parts) > 1 else ""
            authenticated = True
            renew_session(token)
        else:
            command       = data
            authenticated = False

        users = load_user_data()

        # Registration
        if command.startswith("REGISTER"):
            _, username, password = command.split(maxsplit=2)
            if username in users:
                conn.sendall(b"ERROR: Username already exists")
            else:
                pwd_hash, salt = hash_password(password)
                users[username] = {"password_hash": pwd_hash, "salt": salt}
                save_user_data(users)
                conn.sendall(b"OK: Registration successful")

        # Login
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

        # List files
        elif command == "LIST_FILES":
            if not authenticated:
                conn.sendall(b"ERROR: Authentication required")
            else:
                files = list_shared_files()
                conn.sendall("\n".join(files).encode())

        # Download
        elif command.startswith("DOWNLOAD"):
            if not authenticated:
                conn.sendall(b"ERROR: Authentication required\n")
            else:
                try:
                    _, filename = command.split(maxsplit=1)
                    filepath = os.path.join(SHARED_DIR, filename)
                    if not os.path.exists(filepath):
                        conn.sendall(b"ERROR: File not found\n")
                        return

                    # Read, encrypt, and send
                    with open(filepath, "rb") as f:
                        plaintext = f.read()
                    ciphertext = encrypt(plaintext, KEY)
                    filesize = len(ciphertext)

                    # Header + READY handshake
                    conn.sendall(f"SIZE:{filesize}\n".encode())
                    ready = conn.recv(5)
                    if ready != b"READY":
                        raise ConnectionError("Client not ready")

                    # Stream encrypted file in chunks
                    chunk_size = 8192
                    sent = 0
                    while sent < filesize:
                        chunk = ciphertext[sent:sent + chunk_size]
                        conn.sendall(chunk)
                        sent += len(chunk)
                    print(f"[+] File {filename} sent: {sent}/{filesize} bytes")

                except Exception as e:
                    print(f"[-] Download error: {e}")
                    try: conn.sendall(f"ERROR: {e}\n".encode())
                    except: pass

        # Upload
        elif command.startswith("UPLOAD"):
            if not authenticated:
                conn.sendall(b"ERROR: Authentication required")
            else:
                _, filename = command.split(maxsplit=1)
                if not filename.isprintable() or "/" in filename or "\\" in filename:
                    conn.sendall(b"ERROR: Invalid filename")
                else:
                    try:
                        conn.sendall(b"READY")
                        # Read length header
                        header = b""
                        while not header.endswith(b"\n"):
                            header += conn.recv(1)
                        total_len = int(header.decode().strip())

                        # Read ciphertext exactly
                        ciphertext = b""
                        while len(ciphertext) < total_len:
                            chunk = conn.recv(min(4096, total_len - len(ciphertext)))
                            if not chunk:
                                raise ConnectionError("Connection closed during upload")
                            ciphertext += chunk

                        # Decrypt and save to shared_files
                        plaintext = decrypt(ciphertext, KEY)
                        out_path = os.path.join(SHARED_DIR, filename)
                        with open(out_path, "wb") as f:
                            f.write(plaintext)

                        print(f"[+] Received file '{filename}' from {addr}")
                        conn.sendall(b"OK: File uploaded successfully")

                    except Exception as e:
                        print(f"[-] Upload error: {e}")
                        conn.sendall(f"ERROR: Upload failed - {e}".encode())

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
            threading.Thread(
                target=handle_incoming_peer,
                args=(conn, addr),
                daemon=True
            ).start()
