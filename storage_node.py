"""
SecureVault — Storage Node
A lightweight TCP server that stores and retrieves encrypted chunk blobs.
Each node only ever sees ciphertext — it has NO access to keys or IVs.

Wire protocol (length-prefixed, simple & reliable):
  Every message starts with a 4-byte big-endian uint32 = total body length.
  Body is a JSON header followed by a newline, then optional binary payload.

  Request  JSON fields: { "cmd": "STORE"|"FETCH"|"DELETE"|"PING",
                          "file_id": str, "chunk_index": int,
                          "payload_len": int }
  Response JSON fields: { "status": "ok"|"error", "message": str,
                          "payload_len": int }

  STORE:  JSON + '\n' + <encrypted_bytes>  → stores blob to disk
  FETCH:  JSON only                         → responds with JSON + '\n' + blob
  DELETE: JSON only                         → deletes blob from disk
  PING:   JSON only                         → responds {"status":"ok"}
"""

import os
import sys
import json
import struct
import socket
import hashlib
import threading
import argparse


class StorageNode:
    HEADER_SIZE = 4   # bytes for the length prefix

    def __init__(self, node_id: str, host: str, port: int, storage_dir: str):
        self.node_id     = node_id
        self.host        = host
        self.port        = port
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
        self._running = False

    # ── Chunk path helper ─────────────────────────────────────────────────

    def _chunk_path(self, file_id: str, chunk_index: int) -> str:
        sub = os.path.join(self.storage_dir, file_id)
        os.makedirs(sub, exist_ok=True)
        return os.path.join(sub, f"chunk_{chunk_index:05d}.enc")

    # ── Wire protocol helpers ─────────────────────────────────────────────

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed mid-receive")
            buf += chunk
        return buf

    @staticmethod
    def _send_response(sock: socket.socket, status: str,
                       message: str, payload: bytes = b""):
        header = json.dumps({
            "status":      status,
            "message":     message,
            "payload_len": len(payload),
        }).encode() + b"\n"
        body = header + payload
        sock.sendall(struct.pack(">I", len(body)) + body)

    @staticmethod
    def _parse_request(data: bytes) -> tuple[dict, bytes]:
        nl = data.index(b"\n")
        header  = json.loads(data[:nl])
        payload = data[nl + 1 : nl + 1 + header.get("payload_len", 0)]
        return header, payload

    # ── Command handlers ──────────────────────────────────────────────────

    def _handle_store(self, sock, req, payload):
        path = self._chunk_path(req["file_id"], req["chunk_index"])
        with open(path, "wb") as f:
            f.write(payload)
        checksum = hashlib.sha256(payload).hexdigest()[:16]
        self._send_response(sock, "ok", f"stored {len(payload)} bytes | sha256={checksum}")

    def _handle_fetch(self, sock, req, _payload):
        path = self._chunk_path(req["file_id"], req["chunk_index"])
        if not os.path.exists(path):
            self._send_response(sock, "error", "chunk not found")
            return
        with open(path, "rb") as f:
            data = f.read()
        self._send_response(sock, "ok", "fetched", payload=data)

    def _handle_delete(self, sock, req, _payload):
        path = self._chunk_path(req["file_id"], req["chunk_index"])
        if os.path.exists(path):
            os.remove(path)
            self._send_response(sock, "ok", "deleted")
        else:
            self._send_response(sock, "error", "chunk not found")

    def _handle_ping(self, sock, _req, _payload):
        chunks = sum(
            len(files)
            for _, _, files in os.walk(self.storage_dir)
        )
        used = sum(
            f.stat().st_size
            for f in (os.DirEntry for _ in [])   # placeholder
        )
        self._send_response(sock, "ok",
                            f"{self.node_id} alive | chunks on disk: {chunks}")

    # ── Per-connection handler ─────────────────────────────────────────────

    def _handle_client(self, conn: socket.socket, addr):
        try:
            raw_len = self._recv_exact(conn, self.HEADER_SIZE)
            body_len = struct.unpack(">I", raw_len)[0]
            body = self._recv_exact(conn, body_len)
            req, payload = self._parse_request(body)
            cmd = req.get("cmd", "").upper()

            dispatch = {
                "STORE":  self._handle_store,
                "FETCH":  self._handle_fetch,
                "DELETE": self._handle_delete,
                "PING":   self._handle_ping,
            }
            if cmd in dispatch:
                dispatch[cmd](conn, req, payload)
            else:
                self._send_response(conn, "error", f"Unknown command: {cmd}")
        except Exception as e:
            try:
                self._send_response(conn, "error", str(e))
            except Exception:
                pass
        finally:
            conn.close()

    # ── Server loop ───────────────────────────────────────────────────────

    def start(self):
        self._running = True
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(50)
        print(f"[{self.node_id}] Listening on {self.host}:{self.port}  "
              f"storage={self.storage_dir}")
        while self._running:
            try:
                conn, addr = srv.accept()
                t = threading.Thread(target=self._handle_client,
                                     args=(conn, addr), daemon=True)
                t.start()
            except KeyboardInterrupt:
                break
        srv.close()
        print(f"[{self.node_id}] Shut down.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureVault Storage Node")
    parser.add_argument("--id",      default="node_a",   help="Node identifier")
    parser.add_argument("--host",    default="127.0.0.1")
    parser.add_argument("--port",    type=int, default=9001)
    parser.add_argument("--storage", default=None,        help="Storage directory")
    args = parser.parse_args()

    storage_dir = args.storage or os.path.join(
        os.path.dirname(__file__), "..", "data", "chunks", args.id
    )
    node = StorageNode(args.id, args.host, args.port, storage_dir)
    node.start()
