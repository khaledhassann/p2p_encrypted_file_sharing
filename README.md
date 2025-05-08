# CipherShare - Secure P2P File Sharing System

A secure peer-to-peer file sharing system with encryption, authentication, and peer discovery capabilities.

## Features

- **Secure Authentication**
  - Argon2 password hashing
  - Session-based authentication
  - Secure token management

- **End-to-End Encryption**
  - AES-GCM encryption for file transfers
  - Secure key management
  - Encrypted file storage

- **Peer Discovery**
  - Automatic LAN peer discovery
  - UDP broadcast-based peer finding
  - Peer availability monitoring

- **File Operations**
  - Secure file upload/download
  - Progress tracking
  - Chunked file transfer
  - File listing

## Prerequisites

```bash
pip install argon2-cffi cryptography
```

## Project Structure

```
.
├── config.py               # Configuration settings
├── run_peer.py            # Main entry point
├── peer/
│   ├── __init__.py
│   ├── auth.py           # Authentication logic
│   ├── client.py         # Client-side operations
│   ├── crypto_utils.py   # Encryption utilities
│   ├── discovery.py      # Peer discovery
│   ├── file_ops.py       # File operations
│   └── server.py         # Server-side operations
├── shared_files/         # Shared file storage
├── received_files/       # Downloaded files
└── user_data/           # User credentials & keys
```

## Usage

1. Run peer nodes:
```bash
py run_peer.py
```

3. Follow the interactive menu to:
   - Register/Login to peers
   - Share files
   - Download files
   - Discover other peers

## Security Features

- **Password Security**
  - Argon2id hashing algorithm
  - Configurable memory, time, and parallelism parameters
  - Secure salt generation

- **File Security**
  - AES-GCM encryption
  - Unique nonce generation
  - Integrity verification

- **Network Security**
  - Session-based authentication
  - Timeout-based session management
  - Peer availability checking

## Configuration

Key settings in `config.py`:
- `SESSION_TIMEOUT`: Session duration in minutes
- `RENDEZVOUS_PORT`: Port for peer discovery server
- `DISCOVERY_PORT`: UDP port for LAN discovery
- `TCP_DEFAULT_PORT`: Default peer server port

## Directory Structure

- `shared_files/`: Files available for sharing
- `received_files/`: Downloaded files
- `user_data/`: User credentials and encryption keys

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

[MIT License](LICENSE)
