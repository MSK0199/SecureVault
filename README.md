# SecureVault — Distributed File Storage System

**Final Year Project | Integrated M.Tech Software Engineering | VIT-AP**

## Team
| Name | Roll | Module |
|---|---|---|
| Shashwat Kumar | 22MIS7212 | Encryption & Node comms |
| Saif Khan | 22MIS | Auth, RBAC & Flask UI |
| Lekhana | 22MIS | File chunking & Testing |
| Balramreddy | 22MIS | Replication & Fault tolerance |

## Architecture
```
Client (Web UI / CLI)
       │ HTTPS
  API Gateway (Flask)
       │
  ┌────┴──────────────┐
Auth & RBAC    Chunk & Encrypt    Metadata Service
  (JWT)        (AES-256-GCM)      (SQLite)
                    │
           Replication Manager
          ┌─────┬────┴────┐
        Node A  Node B  Node C
      (Encrypted chunks only)
```

## Quick Start

### 1. Install dependencies
```bash
pip install cryptography pyjwt flask
```

### 2. Start storage nodes (3 terminals)
```bash
python scripts/start_nodes.py
```

### 3. Start gateway
```bash
python gateway/gateway.py
```

### 4. Open UI
Visit http://localhost:5000

## Project Structure
```
securevault/
├── core/
│   ├── chunker.py          # File splitting & reassembly
│   ├── encryptor.py        # AES-256-GCM encryption
│   └── metadata.py         # Chunk map & key store (SQLite)
├── nodes/
│   └── storage_node.py     # TCP storage node server
├── gateway/
│   └── gateway.py          # Flask API gateway
├── auth/
│   ├── rbac.py             # Role-based access control
│   └── token.py            # JWT creation & validation
├── ui/
│   └── templates/          # Flask HTML templates
├── tests/
│   └── test_all.py         # Full test suite
└── scripts/
    └── start_nodes.py      # Spin up 3 nodes at once
```
