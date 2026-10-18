"""
SecureVault — Metadata Service
SQLite-backed store for:
  • file registry   (file_id → owner, name, size, hash, created_at)
  • chunk map       (file_id + chunk_index → node locations, hash)
  • key store       (file_id + chunk_index → AES key + IV, base64-encoded)
  • access control  (file_id + user_id → role)

SECURITY NOTE: Encryption keys are stored here, NOT on storage nodes.
In production this service should run in its own hardened process with
encrypted-at-rest SQLite (SQLCipher) or an HSM-backed key store.
"""

import os
import sqlite3
import base64
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager

# Ensure data directory exists
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "metadata.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


# ── DB helpers ─────────────────────────────────────────────────────────────

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables if they don't exist. Safe to call multiple times."""
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS files (
            file_id     TEXT PRIMARY KEY,
            owner_id    TEXT NOT NULL,
            file_name   TEXT NOT NULL,
            file_size   INTEGER NOT NULL,
            total_chunks INTEGER NOT NULL,
            file_hash   TEXT NOT NULL,
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS chunks (
            file_id     TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            chunk_hash  TEXT NOT NULL,
            node_ids    TEXT NOT NULL,   -- JSON list e.g. '["node_a","node_b","node_c"]'
            PRIMARY KEY (file_id, chunk_index),
            FOREIGN KEY (file_id) REFERENCES files(file_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS keys (
            file_id     TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            aes_key_b64 TEXT NOT NULL,
            iv_b64      TEXT NOT NULL,
            PRIMARY KEY (file_id, chunk_index),
            FOREIGN KEY (file_id) REFERENCES files(file_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS access (
            file_id  TEXT NOT NULL,
            user_id  TEXT NOT NULL,
            role     TEXT NOT NULL,
            PRIMARY KEY (file_id, user_id),
            FOREIGN KEY (file_id) REFERENCES files(file_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id      TEXT PRIMARY KEY,
            username     TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at   TEXT NOT NULL
        );
        """)
    print(f"[metadata] DB ready at {DB_PATH}")


# ── File registry ──────────────────────────────────────────────────────────

def register_file(owner_id: str, file_name: str, file_size: int,
                  total_chunks: int, file_hash: str) -> str:
    """Insert a new file record. Returns the generated file_id (UUID)."""
    file_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO files VALUES (?,?,?,?,?,?,?)",
            (file_id, owner_id, file_name, file_size, total_chunks, file_hash, now)
        )
        # Owner gets full access automatically
        conn.execute(
            "INSERT INTO access VALUES (?,?,?)",
            (file_id, owner_id, "owner")
        )
    return file_id


def get_file(file_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
        return dict(row) if row else None


def list_files(user_id: str) -> list[dict]:
    """Return all files the user has any access to."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT f.*, a.role FROM files f
            JOIN access a ON f.file_id = a.file_id
            WHERE a.user_id = ?
            ORDER BY f.created_at DESC
        """, (user_id,)).fetchall()
        return [dict(r) for r in rows]


def delete_file_record(file_id: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM files WHERE file_id=?", (file_id,))


# ── Chunk map ──────────────────────────────────────────────────────────────

def register_chunk(file_id: str, chunk_index: int,
                   chunk_hash: str, node_ids: list[str]):
    import json
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO chunks VALUES (?,?,?,?)",
            (file_id, chunk_index, chunk_hash, json.dumps(node_ids))
        )


def get_chunk_locations(file_id: str) -> list[dict]:
    """Return all chunk records for a file, ordered by index."""
    import json
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM chunks WHERE file_id=? ORDER BY chunk_index",
            (file_id,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["node_ids"] = json.loads(d["node_ids"])
            result.append(d)
        return result


# ── Key store ──────────────────────────────────────────────────────────────

def store_key(file_id: str, chunk_index: int, aes_key: bytes, iv: bytes):
    """Base64-encode key+iv and persist them. Keys must never leave this service."""
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO keys VALUES (?,?,?,?)",
            (file_id, chunk_index,
             base64.b64encode(aes_key).decode(),
             base64.b64encode(iv).decode())
        )


def retrieve_key(file_id: str, chunk_index: int) -> tuple[bytes, bytes] | None:
    """Return (aes_key_bytes, iv_bytes) or None if not found."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT aes_key_b64, iv_b64 FROM keys WHERE file_id=? AND chunk_index=?",
            (file_id, chunk_index)
        ).fetchone()
        if not row:
            return None
        return (base64.b64decode(row["aes_key_b64"]),
                base64.b64decode(row["iv_b64"]))


# ── Access control ─────────────────────────────────────────────────────────

def get_role(file_id: str, user_id: str) -> str | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT role FROM access WHERE file_id=? AND user_id=?",
            (file_id, user_id)
        ).fetchone()
        return row["role"] if row else None


def grant_access(file_id: str, user_id: str, role: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO access VALUES (?,?,?)",
            (file_id, user_id, role)
        )


def revoke_access(file_id: str, user_id: str):
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM access WHERE file_id=? AND user_id=?",
            (file_id, user_id)
        )


# ── User registry ──────────────────────────────────────────────────────────

def register_user(username: str, password_hash: str) -> str:
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users VALUES (?,?,?,?)",
            (user_id, username, password_hash, now)
        )
    return user_id


def get_user_by_username(username: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
        return dict(row) if row else None


if __name__ == "__main__":
    init_db()
    # Quick smoke test
    uid = register_user("alice", "hashed_password_here")
    fid = register_file(uid, "test.txt", 1024, 1, "abc123")
    store_key(fid, 0, b"A" * 32, b"B" * 12)
    key, iv = retrieve_key(fid, 0)
    assert key == b"A" * 32
    assert get_role(fid, uid) == "owner"
    grant_access(fid, "bob_uid", "viewer")
    assert get_role(fid, "bob_uid") == "viewer"
    revoke_access(fid, "bob_uid")
    assert get_role(fid, "bob_uid") is None
    print("[metadata] All smoke tests PASSED")
