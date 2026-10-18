"""
SecureVault — Full integration test suite
Run from project root:  python tests/test_all.py
"""

import os
import sys
import time
import threading
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.encryptor import encrypt_chunk, decrypt_chunk
from core.chunker   import split_bytes, reassemble_bytes, verify_chunk
from core.metadata  import (init_db, register_user, get_user_by_username,
                             register_file, get_file, list_files,
                             register_chunk, get_chunk_locations,
                             store_key, retrieve_key,
                             grant_access, get_role, revoke_access)
from auth.token import create_token, verify_token
from auth.rbac  import has_permission
from config     import NODES
from nodes.storage_node import StorageNode
from nodes.node_client  import ping, store_chunk, fetch_chunk, delete_chunk


PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
results = []


def test(name, fn):
    try:
        fn()
        print(f"  {PASS}  {name}")
        results.append((name, True))
    except Exception as e:
        print(f"  {FAIL}  {name}  →  {e}")
        results.append((name, False))


# ── Encryption tests ───────────────────────────────────────────────────────

def test_encrypt_decrypt():
    data = b"SecureVault test payload " * 1000
    blob, key, iv = encrypt_chunk(data)
    assert decrypt_chunk(blob, key) == data

def test_different_keys_per_chunk():
    chunk = b"same data" * 100
    _, k1, _ = encrypt_chunk(chunk)
    _, k2, _ = encrypt_chunk(chunk)
    assert k1 != k2, "Keys must be unique per chunk"

def test_tamper_detection():
    data = b"tamper test"
    blob, key, iv = encrypt_chunk(data)
    tampered = blob[:-1] + bytes([blob[-1] ^ 0xFF])
    try:
        decrypt_chunk(tampered, key)
        raise AssertionError("Should have raised InvalidTag")
    except Exception as e:
        assert "InvalidTag" in type(e).__name__ or "authentication" in str(e).lower()

def test_wrong_key_rejected():
    data = b"wrong key test"
    blob, key, iv = encrypt_chunk(data)
    bad_key = bytes([k ^ 0xFF for k in key])
    try:
        decrypt_chunk(blob, bad_key)
        raise AssertionError("Should have failed")
    except Exception:
        pass


# ── Chunker tests ──────────────────────────────────────────────────────────

def test_split_and_reassemble():
    data = os.urandom(10 * 1024 * 1024)   # 10 MB
    chunks = split_bytes(data, chunk_size=4 * 1024 * 1024)
    assert len(chunks) == 3, f"Expected 3 chunks, got {len(chunks)}"
    recovered = reassemble_bytes([c for _, c, _ in chunks])
    assert recovered == data

def test_chunk_hash_integrity():
    data = os.urandom(1024)
    chunks = split_bytes(data)
    for idx, chunk, sha in chunks:
        assert verify_chunk(chunk, sha)
        assert not verify_chunk(chunk + b"\x00", sha)

def test_single_chunk_file():
    data = b"tiny file"
    chunks = split_bytes(data)
    assert len(chunks) == 1
    assert reassemble_bytes([c for _, c, _ in chunks]) == data


# ── Metadata tests ─────────────────────────────────────────────────────────

def test_user_register_and_lookup():
    import uuid
    uname = f"testuser_{uuid.uuid4().hex[:6]}"
    uid = register_user(uname, "hashed_pw")
    user = get_user_by_username(uname)
    assert user and user["user_id"] == uid

def test_file_registration():
    uid = register_user(f"fuser_{os.urandom(3).hex()}", "pw")
    fid = register_file(uid, "test.txt", 2048, 2, "abc123")
    rec = get_file(fid)
    assert rec["file_name"] == "test.txt"
    assert get_role(fid, uid) == "owner"

def test_key_store_and_retrieve():
    uid = register_user(f"kuser_{os.urandom(3).hex()}", "pw")
    fid = register_file(uid, "k.bin", 32, 1, "kh")
    key = os.urandom(32)
    iv  = os.urandom(12)
    store_key(fid, 0, key, iv)
    rk, ri = retrieve_key(fid, 0)
    assert rk == key and ri == iv

def test_rbac_grant_revoke():
    uid  = register_user(f"ruser_{os.urandom(3).hex()}", "pw")
    uid2 = register_user(f"ruser2_{os.urandom(3).hex()}", "pw")
    fid  = register_file(uid, "r.txt", 10, 1, "rh")
    assert get_role(fid, uid2) is None
    grant_access(fid, uid2, "viewer")
    assert get_role(fid, uid2) == "viewer"
    revoke_access(fid, uid2)
    assert get_role(fid, uid2) is None


# ── JWT / RBAC tests ───────────────────────────────────────────────────────

def test_token_create_verify():
    token = create_token("user-123", "alice")
    payload = verify_token(token)
    assert payload["sub"] == "user-123"
    assert payload["username"] == "alice"

def test_token_invalid_rejected():
    assert verify_token("not.a.real.token") is None

def test_rbac_permission_check():
    uid = register_user(f"puser_{os.urandom(3).hex()}", "pw")
    uid2 = register_user(f"puser2_{os.urandom(3).hex()}", "pw")
    fid = register_file(uid, "p.txt", 10, 1, "ph")
    # owner can do everything
    for action in ("read", "write", "delete", "manage"):
        assert has_permission(fid, uid, action)
    # stranger gets nothing
    assert not has_permission(fid, uid2, "read")
    # grant viewer
    grant_access(fid, uid2, "viewer")
    assert has_permission(fid, uid2, "read")
    assert not has_permission(fid, uid2, "write")


# ── Storage node + client tests ────────────────────────────────────────────

_test_node = None
_test_node_id = "test_node"
_test_port = 19999

def _start_test_node():
    global _test_node
    storage_dir = tempfile.mkdtemp(prefix="sv_test_")
    _test_node = StorageNode(_test_node_id, "127.0.0.1", _test_port, storage_dir)
    _test_node.start()

def test_node_ping():
    import socket
    for _ in range(20):
        try:
            s = socket.create_connection(("127.0.0.1", _test_port), timeout=0.5)
            s.close()
            break
        except Exception:
            time.sleep(0.1)

    # Use node_client ping
    from nodes.node_client import _send_request
    resp, _ = _send_request("127.0.0.1", _test_port,
                             {"cmd": "PING", "file_id": "", "chunk_index": 0})
    assert resp["status"] == "ok"

def test_node_store_fetch_delete():
    from nodes.node_client import _send_request
    payload = os.urandom(1024)
    fid, idx = "testfile-001", 0

    # STORE
    resp, _ = _send_request("127.0.0.1", _test_port,
                             {"cmd": "STORE", "file_id": fid, "chunk_index": idx},
                             payload=payload)
    assert resp["status"] == "ok"

    # FETCH
    resp, data = _send_request("127.0.0.1", _test_port,
                                {"cmd": "FETCH", "file_id": fid, "chunk_index": idx})
    assert resp["status"] == "ok"
    assert data == payload

    # DELETE
    resp, _ = _send_request("127.0.0.1", _test_port,
                             {"cmd": "DELETE", "file_id": fid, "chunk_index": idx})
    assert resp["status"] == "ok"

    # FETCH after delete → error
    resp, _ = _send_request("127.0.0.1", _test_port,
                             {"cmd": "FETCH", "file_id": fid, "chunk_index": idx})
    assert resp["status"] == "error"


# ── Run all ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n═══ SecureVault Test Suite ═══\n")
    init_db()

    # Start a test node in background
    t = threading.Thread(target=_start_test_node, daemon=True)
    t.start()
    time.sleep(0.3)   # let it bind

    print("── Encryption ────────────────")
    test("encrypt / decrypt round-trip",     test_encrypt_decrypt)
    test("unique key per chunk",             test_different_keys_per_chunk)
    test("tampered ciphertext detected",     test_tamper_detection)
    test("wrong key rejected",               test_wrong_key_rejected)

    print("── Chunker ───────────────────")
    test("10 MB split & reassemble",         test_split_and_reassemble)
    test("chunk SHA-256 integrity",          test_chunk_hash_integrity)
    test("single-chunk file",               test_single_chunk_file)

    print("── Metadata / DB ─────────────")
    test("user register & lookup",           test_user_register_and_lookup)
    test("file registration + owner role",   test_file_registration)
    test("key store & retrieve",             test_key_store_and_retrieve)
    test("RBAC grant & revoke",              test_rbac_grant_revoke)

    print("── Auth / JWT ────────────────")
    test("token create & verify",            test_token_create_verify)
    test("invalid token rejected",           test_token_invalid_rejected)
    test("permission checks",                test_rbac_permission_check)

    print("── Storage Node (live) ───────")
    test("node ping",                        test_node_ping)
    test("store / fetch / delete",           test_node_store_fetch_delete)

    passed = sum(1 for _, ok in results if ok)
    failed = len(results) - passed
    print(f"\n═══ {passed}/{len(results)} passed", end="")
    if failed:
        print(f"  ·  {failed} FAILED ═══\n")
        sys.exit(1)
    else:
        print(" ═══\n")
