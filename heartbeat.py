"""
SecureVault — Heartbeat Monitor & Auto Re-replication Engine
Runs as a background daemon thread inside the gateway process.

Responsibilities:
  1. Ping all nodes every HEARTBEAT_INTERVAL seconds
  2. Mark nodes DEAD after 2 consecutive missed pings
  3. Trigger auto re-replication when a node dies:
       - Find all chunks whose node_ids includes the dead node
       - Fetch each chunk from a live replica
       - Write it to a healthy spare node
       - Update the metadata DB with the new node location
  4. Mark nodes RECOVERED when they come back online
  5. Expose a live status dict for the dashboard
"""

import threading
import time
import json
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import NODES, HEARTBEAT_INTERVAL, NODE_TIMEOUT, REPLICATION_FACTOR
from nodes.node_client import ping, fetch_chunk, _send_request, _node_by_id
import core.metadata as meta

# ── Shared live status (read by the dashboard API) ─────────────────────────
# { node_id: { "alive": bool, "missed": int, "last_seen": str, "chunks": int } }
NODE_STATUS = {n["id"]: {"alive": True, "missed": 0, "last_seen": "—", "chunks": 0}
               for n in NODES}
_status_lock = threading.Lock()

# Track which files have been re-replicated to avoid duplicate work
_rerep_in_progress = set()
_rerep_lock = threading.Lock()


def get_status() -> dict:
    """Return a snapshot of current node status (thread-safe)."""
    with _status_lock:
        return {k: dict(v) for k, v in NODE_STATUS.items()}


# ── Heartbeat loop ─────────────────────────────────────────────────────────

def _heartbeat_loop():
    """Main loop — runs forever in a daemon thread."""
    print("[heartbeat] Monitor started.")
    while True:
        for node in NODES:
            nid = node["id"]
            alive = ping(nid)
            now = datetime.now(timezone.utc).strftime("%H:%M:%S")

            with _status_lock:
                prev_alive = NODE_STATUS[nid]["alive"]
                if alive:
                    NODE_STATUS[nid]["alive"]     = True
                    NODE_STATUS[nid]["missed"]    = 0
                    NODE_STATUS[nid]["last_seen"] = now
                else:
                    NODE_STATUS[nid]["missed"] += 1
                    missed = NODE_STATUS[nid]["missed"]
                    if missed >= 2:
                        NODE_STATUS[nid]["alive"] = False

                current_alive = NODE_STATUS[nid]["alive"]

            # State transitions
            if prev_alive and not current_alive:
                print(f"[heartbeat] ⚠  {nid} is DOWN — triggering re-replication")
                _trigger_rereplicate(nid)

            if not prev_alive and current_alive:
                print(f"[heartbeat] ✓  {nid} is BACK ONLINE")

        time.sleep(HEARTBEAT_INTERVAL)


# ── Auto re-replication ────────────────────────────────────────────────────

def _trigger_rereplicate(dead_node_id: str):
    """
    Spawn a background thread to re-replicate all chunks that were
    on the dead node to a healthy spare node.
    """
    t = threading.Thread(target=_rereplicate_worker,
                         args=(dead_node_id,), daemon=True)
    t.start()


def _rereplicate_worker(dead_node_id: str):
    """
    For every chunk stored on dead_node_id:
      1. Find a live replica node to fetch from
      2. Find a live spare node (not already holding this chunk)
      3. Store the chunk on the spare node
      4. Update the chunk's node_ids in metadata DB
    """
    with _rerep_lock:
        if dead_node_id in _rerep_in_progress:
            return
        _rerep_in_progress.add(dead_node_id)

    try:
        print(f"[rereplicate] Starting re-replication for {dead_node_id}...")

        # Get live node ids
        status = get_status()
        live_nodes = [n["id"] for n in NODES if status.get(n["id"], {}).get("alive")]

        # Find all chunks that had dead_node in their node_ids
        # We scan the metadata DB directly
        import sqlite3
        conn = sqlite3.connect(meta.DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM chunks").fetchall()
        conn.close()

        affected = []
        for row in rows:
            node_ids = json.loads(row["node_ids"])
            if dead_node_id in node_ids:
                affected.append({
                    "file_id":     row["file_id"],
                    "chunk_index": row["chunk_index"],
                    "chunk_hash":  row["chunk_hash"],
                    "node_ids":    node_ids,
                })

        print(f"[rereplicate] Found {len(affected)} chunks to re-replicate")

        replicated = 0
        for chunk_info in affected:
            fid   = chunk_info["file_id"]
            cidx  = chunk_info["chunk_index"]
            nids  = chunk_info["node_ids"]

            # Live replicas = nodes that have this chunk AND are alive
            live_replicas = [n for n in nids if n != dead_node_id and n in live_nodes]
            if not live_replicas:
                print(f"[rereplicate] ✗ No live replica for {fid}:{cidx} — data loss risk!")
                continue

            # Spare node = alive node NOT already holding this chunk
            spare_candidates = [n for n in live_nodes if n not in nids]
            if not spare_candidates:
                print(f"[rereplicate] No spare node available for {fid}:{cidx}")
                continue

            spare_id = spare_candidates[0]

            try:
                # Fetch encrypted blob from a live replica
                blob = fetch_chunk(fid, cidx, live_replicas)

                # Store on spare node
                spare_node = _node_by_id(spare_id)
                resp, _ = _send_request(
                    spare_node["host"], spare_node["port"],
                    {"cmd": "STORE", "file_id": fid, "chunk_index": cidx},
                    payload=blob,
                )
                if resp.get("status") != "ok":
                    raise RuntimeError(resp.get("message", "store failed"))

                # Update metadata: replace dead_node with spare_id
                new_node_ids = [n for n in nids if n != dead_node_id] + [spare_id]
                meta.register_chunk(fid, cidx, chunk_info["chunk_hash"], new_node_ids)
                replicated += 1

            except Exception as e:
                print(f"[rereplicate] ✗ Failed {fid}:{cidx} → {e}")

        print(f"[rereplicate] Done. {replicated}/{len(affected)} chunks re-replicated.")

    finally:
        with _rerep_lock:
            _rerep_in_progress.discard(dead_node_id)


# ── Public start function ──────────────────────────────────────────────────

def start_heartbeat():
    """Call this once at gateway startup to launch the monitor daemon."""
    t = threading.Thread(target=_heartbeat_loop, daemon=True)
    t.start()
    return t
