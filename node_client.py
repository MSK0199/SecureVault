"""
SecureVault — Node Client & Replication Manager
Handles all communication from the gateway to storage nodes.

Responsibilities:
  • store_chunk  — write an encrypted chunk to N nodes (replication)
  • fetch_chunk  — retrieve chunk from the first healthy node that has it
  • delete_chunk — remove chunk from all nodes holding it
  • ping         — heartbeat check on a single node
  • health_check_all — return live/dead status of every configured node
"""

import json
import struct
import socket
import threading
from config import NODES, REPLICATION_FACTOR, NODE_TIMEOUT


# ── Low-level wire protocol ────────────────────────────────────────────────

def _send_request(host: str, port: int, header: dict,
                  payload: bytes = b"") -> tuple[dict, bytes]:
    """
    Send one request to a storage node and return (response_header, payload).
    Raises socket.timeout or ConnectionError on network failure.
    """
    header["payload_len"] = len(payload)
    header_bytes = json.dumps(header).encode() + b"\n"
    body = header_bytes + payload
    frame = struct.pack(">I", len(body)) + body

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(NODE_TIMEOUT)
        s.connect((host, port))
        s.sendall(frame)

        # Read response length prefix
        raw_len = _recv_exact(s, 4)
        body_len = struct.unpack(">I", raw_len)[0]
        resp_body = _recv_exact(s, body_len)

    nl = resp_body.index(b"\n")
    resp_header  = json.loads(resp_body[:nl])
    resp_payload = resp_body[nl + 1 : nl + 1 + resp_header.get("payload_len", 0)]
    return resp_header, resp_payload


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed mid-receive")
        buf += chunk
    return buf


def _node_by_id(node_id: str) -> dict:
    for n in NODES:
        if n["id"] == node_id:
            return n
    raise ValueError(f"Unknown node id: {node_id}")


# ── Public API ─────────────────────────────────────────────────────────────

def ping(node_id: str) -> bool:
    """Return True if the node responds to a PING within NODE_TIMEOUT seconds."""
    try:
        n = _node_by_id(node_id)
        resp, _ = _send_request(n["host"], n["port"],
                                 {"cmd": "PING", "file_id": "", "chunk_index": 0})
        return resp.get("status") == "ok"
    except Exception:
        return False


def health_check_all() -> dict[str, bool]:
    """Return {node_id: is_alive} for every configured node (runs in parallel)."""
    results = {}
    lock = threading.Lock()

    def check(node):
        alive = ping(node["id"])
        with lock:
            results[node["id"]] = alive

    threads = [threading.Thread(target=check, args=(n,), daemon=True) for n in NODES]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=NODE_TIMEOUT + 1)

    # Any node that didn't respond in time counts as dead
    for n in NODES:
        if n["id"] not in results:
            results[n["id"]] = False
    return results


def store_chunk(file_id: str, chunk_index: int,
                encrypted_blob: bytes) -> list[str]:
    """
    Write *encrypted_blob* to REPLICATION_FACTOR healthy nodes.

    Returns list of node_ids where the chunk was successfully stored.
    Raises RuntimeError if fewer than REPLICATION_FACTOR nodes accept the write.
    """
    health = health_check_all()
    live_nodes = [n for n in NODES if health.get(n["id"])]

    if len(live_nodes) < REPLICATION_FACTOR:
        raise RuntimeError(
            f"Only {len(live_nodes)} node(s) alive; need {REPLICATION_FACTOR} for replication."
        )

    stored_on = []
    for node in live_nodes[:REPLICATION_FACTOR]:
        try:
            resp, _ = _send_request(
                node["host"], node["port"],
                {"cmd": "STORE", "file_id": file_id, "chunk_index": chunk_index},
                payload=encrypted_blob,
            )
            if resp.get("status") == "ok":
                stored_on.append(node["id"])
        except Exception as e:
            print(f"[node_client] STORE failed on {node['id']}: {e}")

    if len(stored_on) < REPLICATION_FACTOR:
        raise RuntimeError(
            f"Replication incomplete: stored on {stored_on}, need {REPLICATION_FACTOR}."
        )
    return stored_on


def fetch_chunk(file_id: str, chunk_index: int,
                node_ids: list[str]) -> bytes:
    """
    Retrieve the encrypted blob for (file_id, chunk_index).
    Tries nodes in order, returning data from the first that responds.
    Raises RuntimeError if no node has the chunk.
    """
    for node_id in node_ids:
        try:
            n = _node_by_id(node_id)
            resp, payload = _send_request(
                n["host"], n["port"],
                {"cmd": "FETCH", "file_id": file_id, "chunk_index": chunk_index},
            )
            if resp.get("status") == "ok" and payload:
                return payload
        except Exception as e:
            print(f"[node_client] FETCH failed on {node_id}: {e}")

    raise RuntimeError(
        f"Could not fetch chunk {chunk_index} of file {file_id} from any node."
    )


def delete_chunk(file_id: str, chunk_index: int, node_ids: list[str]):
    """Send DELETE to every node listed — best-effort, logs failures."""
    for node_id in node_ids:
        try:
            n = _node_by_id(node_id)
            _send_request(n["host"], n["port"],
                          {"cmd": "DELETE", "file_id": file_id,
                           "chunk_index": chunk_index})
        except Exception as e:
            print(f"[node_client] DELETE failed on {node_id}: {e}")
