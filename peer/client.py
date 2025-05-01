# peer/client.py

import os
import socket
import tkinter as tk
from tkinter import filedialog
from config import RECEIVED_DIR, RENDEZVOUS_PORT
from peer.crypto_utils import load_key, encrypt, decrypt
import threading
import time

# Load (or generate) the AES-GCM key once
KEY = load_key()

def update_peer_list(rendezvous_ip, my_ip, my_port):
    """Get updated peer list from rendezvous server"""
    try:
        with socket.create_connection((rendezvous_ip, RENDEZVOUS_PORT)) as s:
            s.sendall(f"REGISTER {my_ip} {my_port}".encode())
            data = s.recv(4096).decode()
            
            # Handle empty response (no other peers)
            if not data.strip():
                print("[*] No other peers registered")
                return []

            new_peers = []
            for line in data.split("\n"):
                line = line.strip()
                if line:
                    try:
                        ip, port = line.split()
                        port = int(port)
                        if (ip, port) != (my_ip, my_port):  # Don't add ourselves
                            new_peers.append((ip, port))
                            print(f"[+] Found peer: {ip}:{port}")
                    except ValueError as e:
                        print(f"[-] Invalid peer data: {line}")
                        continue
            return new_peers
    except Exception as e:
        print(f"[-] Failed to update peer list: {e}")
        return None

def peer_client_menu(peers, my_port):  # Add my_port parameter
    session_tokens = {}
    last_update = time.time()
    update_interval = 10  # seconds
    
    # Get my own IP
    my_ip = socket.gethostbyname(socket.gethostname())

    while True:
        # Periodically update peer list
        current_time = time.time()
        if current_time - last_update > update_interval:
            print("[*] Updating peer list...")
            new_peers = update_peer_list("127.0.0.1", my_ip, my_port)  # Use passed-in my_port
            if new_peers is not None:  # Only update if successful
                peers = new_peers
            last_update = current_time

        # Add debug output
        print(f"[*] Checking {len(peers)} peers...")
        # Remove disconnected peers with debug info
        active_peers = []
        for ip, port in peers:
            if check_peer_alive(ip, port):
                active_peers.append((ip, port))
                print(f"[+] Peer {ip}:{port} is alive")
        peers = active_peers
        
        if not peers:
            print("[!] No active peers available")
            print("[*] Waiting for peers to connect...")
            time.sleep(5)  # Wait 5 seconds before checking again
            continue  # Instead of return, continue the loop
            
        print("\n=== Peer Client Menu ===")
        print("1. Login/Register to a peer")
        print("2. List files on a peer")
        print("3. Download file from a peer")
        print("4. Upload file to a peer")
        print("5. Exit")

        choice = input("Select an option (1-5): ").strip()
        if choice == "5":
            break
        if choice not in {"1", "2", "3", "4"}:
            continue

        peer_ip, peer_port = select_peer(peers)
        if peer_ip is None:
            continue

        if choice == "1":
            token = authenticate_with_peer(peer_ip, peer_port)
            if token:
                session_tokens[(peer_ip, peer_port)] = token

        else:
            token = session_tokens.get((peer_ip, peer_port))
            if not token:
                print("Please login/register to this peer first!")
                continue
            if choice == "2":
                list_files(peer_ip, peer_port, token)
            elif choice == "3":
                download_file(peer_ip, peer_port, token)
            elif choice == "4":
                upload_file(peer_ip, peer_port, token)


def select_peer(peers):
    if not peers:
        print("[!] No peers available.")
        return None, None
        
    # Show only active peers
    active_peers = []
    for ip, port in peers:
        if check_peer_alive(ip, port):
            active_peers.append((ip, port))
            print(f"{len(active_peers)}. {ip}:{port} (ONLINE)")
        else:
            print(f"X. {ip}:{port} (OFFLINE)")
            
    if not active_peers:
        print("[!] No active peers available")
        return None, None
        
    try:
        idx = int(input("Select peer number: ").strip()) - 1
        return active_peers[idx]
    except (ValueError, IndexError):
        print("[!] Invalid selection")
        return None, None


def authenticate_with_peer(ip, port):
    with socket.create_connection((ip, port)) as s:
        print("1) Login\n2) Register")
        choice = input("Option: ").strip()
        user = input("Username: ")
        pwd = input("Password: ")
        cmd = "LOGIN" if choice == "1" else "REGISTER"
        s.sendall(f"{cmd} {user} {pwd}".encode())
        resp = s.recv(1024).decode()
        if resp.startswith("OK:"):
            token = resp.split("OK:")[1].strip()
            print("[+] Authenticated, token:", token)
            return token
        else:
            print("[-]", resp)
            return None


def list_files(ip, port, token):
    with socket.create_connection((ip, port)) as s:
        s.sendall(f"{token} LIST_FILES".encode())
        data = s.recv(4096).decode()
        print("\n" + data)


def download_file(ip, port, token):
    try:
        # Increase timeout to handle larger files
        with socket.create_connection((ip, port), timeout=30) as s:
            # Get file list and selection
            s.sendall(f"{token} LIST_FILES".encode())
            files = s.recv(4096).decode().split("\n")
            for i, f in enumerate(files, start=1):
                print(f"{i}. {f}")
            idx = int(input("File number: ").strip()) - 1
            filename = files[idx].strip()

            print(f"[*] Requesting download of '{filename}'...")
            s.sendall(f"{token} DOWNLOAD {filename}".encode())
            
            # Read length header
            header = b""
            while b"\n" not in header:
                chunk = s.recv(1024)
                if not chunk:
                    raise ConnectionError("Connection closed while reading header")
                header += chunk
            
            # Parse total length
            total_len = int(header[:header.index(b"\n")].decode())
            print(f"[*] File size: {total_len} bytes")
            
            # Read file data in chunks
            ciphertext = b""
            chunk_size = 8192  # Larger chunk size
            
            while len(ciphertext) < total_len:
                remaining = total_len - len(ciphertext)
                to_read = min(chunk_size, remaining)
                
                chunk = s.recv(to_read)
                if not chunk:
                    raise ConnectionError(f"Connection closed after receiving {len(ciphertext)} of {total_len} bytes")
                
                ciphertext += chunk
                percent = (len(ciphertext) / total_len) * 100
                print(f"\rDownloading: {percent:.1f}% ({len(ciphertext)}/{total_len} bytes)", end="", flush=True)
            
            print("\n[*] Download complete, decrypting...")
            
            try:
                plaintext = decrypt(ciphertext, KEY)
                os.makedirs(RECEIVED_DIR, exist_ok=True)
                out_path = os.path.join(RECEIVED_DIR, filename)
                
                with open(out_path, "wb") as f:
                    f.write(plaintext)
                print(f"[+] File saved to {out_path}")
                
            except Exception as e:
                raise Exception(f"Decryption/save failed: {str(e)}")
                
    except Exception as e:
        print(f"[-] Download failed: {str(e)}")
        return None


def upload_file(ip, port, token):
    # --- bring up a hidden Tk root so dialogs work reliably ---
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)  # ensure the dialog floats above all windows
    root.update()                      # force an initial draw/update

    filepath = filedialog.askopenfilename(title="Select file to upload")
    root.destroy()                     # clean up the hidden root

    if not filepath:
        print("Upload cancelled")
        return

    filename = os.path.basename(filepath)
    print(f"[*] Reading file: {filepath}")
    
    with open(filepath, "rb") as f:
        plaintext = f.read()

    print(f"[*] Encrypting {len(plaintext)} bytes...")
    ciphertext = encrypt(plaintext, KEY)

    print(f"[*] Uploading to {ip}:{port}...")
    with socket.create_connection((ip, port)) as s:
        s.sendall(f"{token} UPLOAD {filename}".encode())
        resp = s.recv(1024).decode()
        if resp != "READY":
            print(f"[-] Server error: {resp}")
            return

        # Send length header + newline
        s.sendall(f"{len(ciphertext)}\n".encode())
        # Send ciphertext bytes
        s.sendall(ciphertext)

        # Wait for confirmation
        final = s.recv(1024).decode()
        if final.startswith("OK:"):
            print(f"[+] File '{filename}' uploaded successfully")
        else:
            print(f"[-] Upload failed: {final}")


def check_peer_alive(ip, port):
    """Check if a peer is still responsive"""
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.sendall(b"PING")
            try:
                response = s.recv(4)
                return response == b"PONG"
            except socket.timeout:
                return False
    except (socket.timeout, ConnectionRefusedError, OSError):
        print(f"[-] Failed to connect to peer {ip}:{port}")
        return False
