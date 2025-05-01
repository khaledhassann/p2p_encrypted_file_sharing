# # rendezvous_server.py

# import socket
# import threading

# HOST = '0.0.0.0'
# PORT = 5000
# peers = []

# def handle_client(conn, addr):
#     try:
#         data = conn.recv(1024).decode().strip()
#         if data.startswith("REGISTER"):
#             _, peer_ip, peer_port = data.split()
#             peer_port = int(peer_port)
#             if (peer_ip, peer_port) not in peers:
#                 peers.append((peer_ip, peer_port))
#                 print(f"[+] Peer registered: {peer_ip}:{peer_port}")
            
#             # Send back list of peers (excluding the newly registered peer)
#             known_peers = "\n".join(f"{ip} {port}" for ip, port in peers if (ip, port) != (peer_ip, peer_port))
#             conn.sendall(known_peers.encode())
#     except Exception as e:
#         print(f"[!] Error handling peer: {e}")
#     finally:
#         conn.close()

# def start_rendezvous_server():
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.bind((HOST, PORT))
#         s.listen()
#         print(f"[*] Rendezvous server listening on {HOST}:{PORT}")
#         while True:
#             conn, addr = s.accept()
#             threading.Thread(target=handle_client, args=(conn, addr)).start()

# if __name__ == "__main__":
#     start_rendezvous_server()
