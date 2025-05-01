# rendezvous/server.py

import socket
import threading
from config import RENDEZVOUS_PORT

peers = []

def handle_client(conn, addr):
    try:
        data = conn.recv(1024).decode().strip()
        if data.startswith("REGISTER"):
            try:
                # Parse the registration command
                _, ip, port = data.split()
                port = int(port)  # Convert port to integer
                
                # Add to peers list if not already present
                if (ip, port) not in peers:
                    peers.append((ip, port))
                    print(f"[+] Peer registered: {ip}:{port}")
                
                # Send back list of other peers
                other_peers = [(p_ip, p_port) for p_ip, p_port in peers if (p_ip, p_port) != (ip, port)]
                if other_peers:
                    listing = "\n".join(f"{p[0]} {p[1]}" for p in other_peers)
                else:
                    listing = ""  # Empty string if no other peers
                conn.sendall(listing.encode())
                
            except (ValueError, IndexError) as e:
                print(f"[!] Invalid registration format: {data}")
                conn.sendall(b"ERROR: Invalid registration format")
                
    except Exception as e:
        print(f"[!] Rendezvous error: {e}")
    finally:
        conn.close()

def start_rendezvous_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", RENDEZVOUS_PORT))
        s.listen()
        print(f"[*] Rendezvous listening on port {RENDEZVOUS_PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn,addr), daemon=True).start()

if __name__ == "__main__":
    start_rendezvous_server()
