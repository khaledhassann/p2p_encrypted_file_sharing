# peer/client.py

import os
import socket
import tkinter as tk
from tkinter import filedialog
from config import RECEIVED_DIR, DISCOVERY_PORT
from peer.discovery import discover_peers
from peer.crypto_utils import load_key, encrypt, decrypt
import time

# Load (or generate) the AES-GCM key once
KEY = load_key()

def peer_client_menu(peers):

    session_tokens = {}

    while True:
        # 1) Prune any peers that have gone offline
        active_peers = []
        for ip, port in peers:
            if check_peer_alive(ip, port):
                active_peers.append((ip, port))
        peers = active_peers

        if not peers:
            print("[!] No active peers available.")
        else:
            print(f"[*] {len(peers)} peer(s) online.")

        # 2) Show menu
        print("\n=== Peer Client Menu ===")
        print("1. Login/Register to a peer")
        print("2. List files on a peer")
        print("3. Download file from a peer")
        print("4. Upload file to a peer")
        print("5. Discover peers on LAN")
        print("6. Exit")

        choice = input("Select an option (1-6): ").strip()

        # 3) Exit
        if choice == "6":
            break

        # 4) Manual discovery
        if choice == "5":
            print(f"[*] Broadcasting discovery on UDP port {DISCOVERY_PORT}...")
            new_peers = discover_peers(timeout=2.0)
            if new_peers:
                print(f"[+] Found peers: {new_peers}")
                for p in new_peers:
                    if p not in peers:
                        peers.append(p)
            else:
                print("[*] No new peers found.")
            continue  # back to top of loop

        # 5) Actions 1–4 require selecting a peer
        if choice not in {"1", "2", "3", "4"}:
            continue

        peer_ip, peer_port = select_peer(peers)
        if peer_ip is None:
            continue

        # 6) Perform the chosen action
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
    # Implement a more robust download method
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(30)  # Set timeout to 30 seconds
        s.connect((ip, port))
        
        # Get file list
        s.sendall(f"{token} LIST_FILES".encode())
        files_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            files_data += chunk
            if len(chunk) < 4096:  # If received less than full buffer, likely done
                break
                
        files = [f.strip() for f in files_data.decode().split("\n") if f.strip()]
        
        if not files:
            print("No files available")
            if s:
                s.close()
            return None

        for i, f in enumerate(files, 1):
            print(f"{i}. {f}")
        try:
            idx = int(input("File number: ")) - 1
            filename = files[idx]
        except (ValueError, IndexError):
            print("Invalid selection")
            if s:
                s.close()
            return None

        # Close the first connection
        s.close()
        
        # Create a new connection for the download
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(60)  # Longer timeout for download
        s.connect((ip, port))
        
        # Request download
        s.sendall(f"{token} DOWNLOAD {filename}".encode())

        # Read size header or error
        header = b""
        while b"\n" not in header:
            chunk = s.recv(1)
            if not chunk:
                raise ConnectionError("Connection closed while reading header")
            header += chunk

        if header.startswith(b"ERROR:"):
            print(f"\n[-] Server error: {header.decode()}")
            s.close()
            return None

        # Extract size from the header
        try:
            size_part = header[:header.index(b"\n")].decode()
            if not size_part.startswith("SIZE:"):
                print("\n[-] Invalid server response format")
                s.close()
                return None
                
            filesize = int(size_part[5:])
            print(f"Downloading {filesize} bytes...")
        except (ValueError, IndexError) as e:
            print(f"\n[-] Invalid size format: {e}")
            s.close()
            return None

        # Send READY signal
        s.sendall(b"READY")

        # Download encrypted bytes with progress reporting
        received = 0
        ciphertext = b""
        
        while received < filesize:
            remaining = filesize - received
            chunk_size = min(8192, remaining)
            
            try:
                chunk = s.recv(chunk_size)
                if not chunk:
                    # If server closed connection but we haven't received all data
                    if received < filesize:
                        print(f"\n[-] Connection closed after receiving {received}/{filesize} bytes")
                        s.close()
                        return None
                    break
                    
                ciphertext += chunk
                received += len(chunk)
                print(f"\r{received}/{filesize} bytes ({received/filesize:.1%})", end="", flush=True)
                
            except socket.timeout:
                print("\n[-] Timeout while downloading")
                s.close()
                return None

        print("\n[+] Download complete, decrypting...")

        # Decrypt and save
        try:
            plaintext = decrypt(ciphertext, KEY)
            os.makedirs(RECEIVED_DIR, exist_ok=True)
            out_path = os.path.join(RECEIVED_DIR, filename)
            with open(out_path, "wb") as f:
                f.write(plaintext)
            print(f"[+] File saved to {out_path}")
            s.close()
            return out_path
        except Exception as e:
            print(f"\n[-] Decryption failed: {e}")
            s.close()
            return None

    except Exception as e:
        print(f"\n[-] Download failed: {e}")
        if s:
            s.close()
        return None


# def download_file(ip, port, token):
#     try:
#         # Increase timeout to handle larger files
#         with socket.create_connection((ip, port), timeout=30) as s:
#             # Get file list and selection
#             s.sendall(f"{token} LIST_FILES".encode())
#             files = s.recv(4096).decode().split("\n")
#             for i, f in enumerate(files, start=1):
#                 print(f"{i}. {f}")
#             idx = int(input("File number: ").strip()) - 1
#             filename = files[idx].strip()

#             print(f"[*] Requesting download of '{filename}'...")
#             s.sendall(f"{token} DOWNLOAD {filename}".encode())
            
#             # Read length header
#             header = b""
#             while b"\n" not in header:
#                 chunk = s.recv(1024)
#                 if not chunk:
#                     raise ConnectionError("Connection closed while reading header")
#                 header += chunk
            
#             # Parse total length
#             total_len = int(header[:header.index(b"\n")].decode())
#             print(f"[*] File size: {total_len} bytes")
            
#             # Read file data in chunks
#             ciphertext = b""
#             chunk_size = 8192  # Larger chunk size
            
#             while len(ciphertext) < total_len:
#                 remaining = total_len - len(ciphertext)
#                 to_read = min(chunk_size, remaining)
                
#                 chunk = s.recv(to_read)
#                 if not chunk:
#                     raise ConnectionError(f"Connection closed after receiving {len(ciphertext)} of {total_len} bytes")
                
#                 ciphertext += chunk
#                 percent = (len(ciphertext) / total_len) * 100
#                 print(f"\rDownloading: {percent:.1f}% ({len(ciphertext)}/{total_len} bytes)", end="", flush=True)
            
#             print("\n[*] Download complete, decrypting...")
            
#             try:
#                 plaintext = decrypt(ciphertext, KEY)
#                 os.makedirs(RECEIVED_DIR, exist_ok=True)
#                 out_path = os.path.join(RECEIVED_DIR, filename)
                
#                 with open(out_path, "wb") as f:
#                     f.write(plaintext)
#                 print(f"[+] File saved to {out_path}")
                
#             except Exception as e:
#                 raise Exception(f"Decryption/save failed: {str(e)}")
                
#     except Exception as e:
#         print(f"[-] Download failed: {str(e)}")
#         return None


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
