# run_peer.py

import threading
import socket
from config import RENDEZVOUS_PORT
from peer.server import start_peer_server
from peer.client import peer_client_menu

def main():
    # 1) Ask your own listening port
    my_port = int(input("Enter your peer server port: ").strip())

    # 2) Ask the rendezvous server address
    rendezvous_ip = input("Enter Rendezvous Server IP [127.0.0.1]: ").strip() or "127.0.0.1"

    # 3) Start your peer server in background
    threading.Thread(target=start_peer_server, args=(my_port,), daemon=True).start()

    # 4) Register yourself with the rendezvous server
    my_ip = socket.gethostbyname(socket.gethostname())
    with socket.create_connection((rendezvous_ip, RENDEZVOUS_PORT)) as s:
        s.sendall(f"REGISTER {my_ip} {my_port}".encode())
        data = s.recv(4096).decode()

    # 5) Parse list of known peers
    peers = []
    for line in data.split("\n"):
        line = line.strip()
        if not line:
            continue
        ip, port = line.split()
        peers.append((ip, int(port)))

    print("[+] Discovered peers:", peers)

    # 6) Enter the interactive menu with necessary info
    peer_client_menu(peers, my_port)  # Pass my_port as parameter


if __name__ == "__main__":
    main()
