# # peer.py

# import os
# import socket
# import threading
# import hashlib
# import secrets
# import json
# from datetime import datetime, timedelta
# import tkinter as tk
# from tkinter import filedialog

# SHARED_DIR = "shared_files"
# RECEIVED_DIR = "received_files"
# USER_DATA_FILE = "user_data/users.json"
# SESSION_TIMEOUT = 30  # minutes
# RENDEZVOUS_PORT = 5000

# os.makedirs(SHARED_DIR, exist_ok=True)
# os.makedirs(RECEIVED_DIR, exist_ok=True)
# os.makedirs(os.path.dirname(USER_DATA_FILE), exist_ok=True)

# active_sessions = {}

# # --- User Authentication Helpers ---

# def load_user_data():
#     if not os.path.exists(USER_DATA_FILE):
#         with open(USER_DATA_FILE, 'w') as f:
#             json.dump({}, f)
#     with open(USER_DATA_FILE, 'r') as f:
#         return json.load(f)

# def save_user_data(users):
#     with open(USER_DATA_FILE, 'w') as f:
#         json.dump(users, f)

# def hash_password(password, salt=None):
#     if salt is None:
#         salt = secrets.token_hex(16)
#     hashed = hashlib.sha256((password + salt).encode()).hexdigest()
#     return hashed, salt

# def verify_password(stored_hash, salt, input_password):
#     input_hash = hashlib.sha256((input_password + salt).encode()).hexdigest()
#     return input_hash == stored_hash

# # --- Peer Server: Handle incoming requests ---

# def handle_incoming_peer(conn, addr):
#     try:
#         data = conn.recv(1024).decode().strip()
#         if not data:
#             return
        
#         authenticated = False
#         if ' ' in data and len(data.split()[0]) == 32:
#             session_token, command = data.split(maxsplit=1)
#             if session_token in active_sessions and datetime.now() < active_sessions[session_token]["expiry"]:
#                 authenticated = True
#                 # Renew session
#                 active_sessions[session_token]["expiry"] = datetime.now() + timedelta(minutes=SESSION_TIMEOUT)
#         else:
#             command = data

#         users = load_user_data()

#         if command.startswith("REGISTER"):
#             _, username, password = command.split(maxsplit=2)
#             if username in users:
#                 conn.sendall(b"ERROR: Username already exists")
#             else:
#                 password_hash, salt = hash_password(password)
#                 users[username] = {"password_hash": password_hash, "salt": salt}
#                 save_user_data(users)
#                 conn.sendall(b"OK: Registration successful")

#         elif command.startswith("LOGIN"):
#             _, username, password = command.split(maxsplit=2)
#             if username not in users:
#                 conn.sendall(b"ERROR: User not found")
#             else:
#                 user_data = users[username]
#                 if verify_password(user_data["password_hash"], user_data["salt"], password):
#                     token = secrets.token_hex(16)
#                     active_sessions[token] = {"username": username, "expiry": datetime.now() + timedelta(minutes=SESSION_TIMEOUT)}
#                     conn.sendall(f"OK: {token}".encode())
#                 else:
#                     conn.sendall(b"ERROR: Invalid password")

#         elif command == "LIST_FILES":
#             if not authenticated:
#                 conn.sendall(b"ERROR: Authentication required")
#             else:
#                 files = os.listdir(SHARED_DIR)
#                 conn.sendall("\n".join(files).encode())

#         elif command.startswith("DOWNLOAD"):
#             if not authenticated:
#                 conn.sendall(b"ERROR: Authentication required")
#             else:
#                 requested_file = command.split(maxsplit=1)[1]
#                 file_path = os.path.join(SHARED_DIR, requested_file)
#                 if os.path.exists(file_path):
#                     with open(file_path, "rb") as f:
#                         while True:
#                             chunk = f.read(4096)
#                             if not chunk:
#                                 break
#                             conn.sendall(chunk)
#                     conn.sendall(b"<EOF>")
#                 else:
#                     conn.sendall(b"ERROR: File not found")

#         elif command.startswith("UPLOAD"):
#             if not authenticated:
#                 conn.sendall(b"ERROR: Authentication required")
#             else:
#                 filename = command.split(maxsplit=1)[1]
#                 if not filename.isprintable() or '/' in filename:
#                     conn.sendall(b"ERROR: Invalid filename")
#                     return
#                 file_path = os.path.join(SHARED_DIR, filename)
#                 conn.sendall(b"READY")

#                 with open(file_path, "wb") as f:
#                     while True:
#                         data = conn.recv(4096)
#                         if data.endswith(b"<EOF>"):
#                             f.write(data[:-5])
#                             break
#                         f.write(data)
#                 conn.sendall(b"OK: File uploaded successfully")

#         else:
#             conn.sendall(b"ERROR: Unknown command")
#     except Exception as e:
#         print(f"[!] Error: {e}")
#     finally:
#         conn.close()

# def start_peer_server(port):
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.bind(('0.0.0.0', port))
#         s.listen()
#         print(f"[*] Peer server listening on port {port}...")
#         while True:
#             conn, addr = s.accept()
#             threading.Thread(target=handle_incoming_peer, args=(conn, addr)).start()

# # --- Peer Client Menu ---

# def peer_client_menu(peers):
#     session_token = None
#     peer_sessions = {}

#     while True:
#         print("\n=== Peer Client Menu ===")
#         print("1. Connect to a peer and Login/Register")
#         print("2. List available files")
#         print("3. Download file")
#         print("4. Upload file")
#         print("5. Exit")

#         choice = input("Select an option (1-5): ")

#         if choice == "1":
#             peer_ip, peer_port = select_peer(peers)
#             session_token = authenticate_with_peer(peer_ip, peer_port)
#             peer_sessions[(peer_ip, peer_port)] = session_token


#         elif choice == "2":
#             session_token = peer_sessions.get((peer_ip, peer_port))
#             if not session_token:
#                 print("You must login/register to this peer first!")
#                 continue

#             peer_ip, peer_port = select_peer(peers)
#             list_files(peer_ip, peer_port, session_token)

#         elif choice == "3":
#             session_token = peer_sessions.get((peer_ip, peer_port))
#             if not session_token:
#                 print("You must login/register to this peer first!")
#                 continue
#             peer_ip, peer_port = select_peer(peers)
#             download_file(peer_ip, peer_port, session_token)

#         elif choice == "4":
#             session_token = peer_sessions.get((peer_ip, peer_port))
#             if not session_token:
#                 print("You must login/register to this peer first!")
#                 continue
#             peer_ip, peer_port = select_peer(peers)
#             upload_file(peer_ip, peer_port, session_token)

#         elif choice == "5":
#             print("Goodbye!")
#             break

# def select_peer(peers):
#     if not peers:
#         print("[!] No peers available yet. Try again later.")
#         return None, None

#     print("\nAvailable Peers:")
#     for idx, (ip, port) in enumerate(peers):
#         print(f"{idx+1}. {ip}:{port}")
#     choice = int(input("Select peer number: ")) - 1
#     return peers[choice]


# def authenticate_with_peer(ip, port):
#     with socket.create_connection((ip, port)) as s:
#         print("\nAuthentication Menu:")
#         print("1. Login")
#         print("2. Register")
#         auth_choice = input("Select option: ")

#         username = input("Username: ")
#         password = input("Password: ")

#         if auth_choice == "1":
#             s.sendall(f"LOGIN {username} {password}".encode())
#         elif auth_choice == "2":
#             s.sendall(f"REGISTER {username} {password}".encode())
#         else:
#             print("Invalid choice")
#             return None

#         response = s.recv(1024).decode()
#         if response.startswith("OK:"):
#             print("[+] Authentication successful!")
#             if " " in response:
#                 return response.split(": ")[1].strip()
#         else:
#             print(f"[!] Authentication failed: {response}")
#             return None

# def list_files(ip, port, token):
#     with socket.create_connection((ip, port)) as s:
#         s.sendall(f"{token} LIST_FILES".encode())
#         files = s.recv(4096).decode()
#         print("\nAvailable files:")
#         print(files)

# def download_file(ip, port, token):
#     with socket.create_connection((ip, port)) as s:
#         s.sendall(f"{token} LIST_FILES".encode())
#         files = s.recv(4096).decode().split("\n")
#         for idx, f in enumerate(files):
#             print(f"{idx+1}. {f}")

#         file_choice = int(input("Select file number: ")) - 1
#         filename = files[file_choice]
#         s.sendall(f"{token} DOWNLOAD {filename}".encode())

#         with open(f"{RECEIVED_DIR}/{filename}", "wb") as f:
#             while True:
#                 try:
#                     chunk = s.recv(4096)
#                     if not chunk:
#                         # Connection closed
#                         break
#                     if b"<EOF>" in chunk:
#                         f.write(chunk.replace(b"<EOF>", b""))  # Remove marker
#                         break
#                     f.write(chunk)
#                 except Exception as e:
#                     print(f"[!] Download error: {e}")
#                     break

#         print(f"[+] File '{filename}' downloaded successfully into '{RECEIVED_DIR}/'")



# def upload_file(ip, port, token):
#     root = tk.Tk()
#     root.withdraw()
#     root.attributes('-topmost', True)

#     filepath = filedialog.askopenfilename(title="Select file to upload")
#     root.destroy()

#     if not filepath:
#         print("Upload cancelled")
#         return

#     filename = os.path.basename(filepath)

#     with socket.create_connection((ip, port)) as s:
#         s.sendall(f"{token} UPLOAD {filename}".encode())
#         response = s.recv(1024)
#         if response != b"READY":
#             print(f"Server error: {response.decode()}")
#             return

#         with open(filepath, "rb") as f:
#             while True:
#                 chunk = f.read(4096)
#                 if not chunk:
#                     break
#                 s.sendall(chunk)
#         s.sendall(b"<EOF>")

#         final_response = s.recv(1024).decode()
#         print(final_response)

# # --- Main ---

# if __name__ == "__main__":
#     my_port = int(input("Enter your peer server port: "))
#     rendezvous_ip = input("Enter Rendezvous Server IP: ")

#     threading.Thread(target=start_peer_server, args=(my_port,), daemon=True).start()

#     my_ip = socket.gethostbyname(socket.gethostname())

#     with socket.create_connection((rendezvous_ip, RENDEZVOUS_PORT)) as s:
#         s.sendall(f"REGISTER {my_ip} {my_port}".encode())
#         data = s.recv(4096).decode()

#     peers = []
#     if data.strip():
#         for line in data.split("\n"):
#             ip, port = line.split()
#             peers.append((ip, int(port)))

#     print("[+] Peers discovered:", peers)

#     peer_client_menu(peers)
