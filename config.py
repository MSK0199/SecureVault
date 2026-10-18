"""
SecureVault — Central configuration
All tunable parameters live here so nothing is hardcoded elsewhere.
"""

import os

# ── Storage nodes ──────────────────────────────────────────────
NODES = [
    {"id": "node_a", "host": "127.0.0.1", "port": 9001},
    {"id": "node_b", "host": "127.0.0.1", "port": 9002},
    {"id": "node_c", "host": "127.0.0.1", "port": 9003},
]

REPLICATION_FACTOR = 3          # how many nodes each chunk is written to
HEARTBEAT_INTERVAL = 5          # seconds between health pings
NODE_TIMEOUT       = 10         # seconds before a node is declared dead

# ── Chunking ───────────────────────────────────────────────────
CHUNK_SIZE_BYTES = 4 * 1024 * 1024   # 4 MB per chunk

# ── Encryption ────────────────────────────────────────────────
AES_KEY_BITS = 256                   # 256-bit AES-GCM
TAG_LENGTH   = 16                    # GCM authentication tag (bytes)

# ── Auth / JWT ────────────────────────────────────────────────
JWT_SECRET     = os.environ.get("SV_JWT_SECRET", "change-me-in-production-32chars!!")
JWT_ALGORITHM  = "HS256"
JWT_EXPIRY_HRS = 8

# ── Metadata DB ───────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "metadata.db")

# ── Gateway ───────────────────────────────────────────────────
GATEWAY_HOST = "0.0.0.0"
GATEWAY_PORT = 5000
MAX_UPLOAD_MB = 500

# ── Roles ─────────────────────────────────────────────────────
ROLES = {
    "owner":  {"read", "write", "delete", "manage"},
    "editor": {"read", "write"},
    "viewer": {"read"},
}
