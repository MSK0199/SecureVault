"""
SecureVault — API Gateway (Flask)
Serves the web UI and all REST API routes.
"""

import os, sys, hashlib, io
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, request, jsonify, send_file, render_template, redirect
from functools import wraps

from config import GATEWAY_HOST, GATEWAY_PORT, MAX_UPLOAD_MB
import core.metadata as meta
import core.chunker  as chunker
import core.encryptor as enc
import nodes.node_client as nc
from nodes.heartbeat import start_heartbeat, get_status
from auth.token import create_token, verify_token
from auth.rbac  import has_permission, require_permission

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "ui", "templates")
app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.secret_key = "securevault-ui-secret"

meta.init_db()

# ── Auth decorator ─────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        payload = verify_token(auth[7:])
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        request.user_id  = payload["sub"]
        request.username = payload["username"]
        return f(*args, **kwargs)
    return decorated

# ── UI Routes ──────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/nodes")
def nodes_page():
    return render_template("nodes.html")

# ── API: Auth ──────────────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    username = (data or {}).get("username", "").strip()
    password = (data or {}).get("password", "")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if meta.get_user_by_username(username):
        return jsonify({"error": "Username already taken"}), 409
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    user_id = meta.register_user(username, pw_hash)
    token   = create_token(user_id, username)
    return jsonify({"user_id": user_id, "token": token}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = (data or {}).get("username", "").strip()
    password = (data or {}).get("password", "")
    user = meta.get_user_by_username(username)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    if hashlib.sha256(password.encode()).hexdigest() != user["password_hash"]:
        return jsonify({"error": "Invalid credentials"}), 401
    token = create_token(user["user_id"], user["username"])
    return jsonify({"token": token, "user_id": user["user_id"]})

# ── API: Files ─────────────────────────────────────────────────────────────
@app.route("/api/files", methods=["GET"])
@login_required
def list_files():
    return jsonify({"files": meta.list_files(request.user_id)})

@app.route("/api/files/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file in request"}), 400
    f         = request.files["file"]
    file_data = f.read()
    file_name = f.filename or "upload"
    file_hash = hashlib.sha256(file_data).hexdigest()
    chunks    = chunker.split_bytes(file_data)
    file_id   = meta.register_file(request.user_id, file_name,
                                   len(file_data), len(chunks), file_hash)
    for idx, chunk_bytes, chunk_hash in chunks:
        blob, key, iv = enc.encrypt_chunk(chunk_bytes)
        node_ids = nc.store_chunk(file_id, idx, blob)
        meta.register_chunk(file_id, idx, chunk_hash, node_ids)
        meta.store_key(file_id, idx, key, iv)
    return jsonify({"file_id": file_id, "file_name": file_name,
                    "file_size": len(file_data), "total_chunks": len(chunks),
                    "message": "Upload successful"}), 201

@app.route("/api/files/<file_id>", methods=["GET"])
@login_required
def file_info(file_id):
    try: require_permission(file_id, request.user_id, "read")
    except PermissionError as e: return jsonify({"error": str(e)}), 403
    rec = meta.get_file(file_id)
    if not rec: return jsonify({"error": "File not found"}), 404
    return jsonify({"file": rec, "chunks": meta.get_chunk_locations(file_id)})

@app.route("/api/files/<file_id>/download", methods=["GET"])
@login_required
def download_file(file_id):
    try: require_permission(file_id, request.user_id, "read")
    except PermissionError as e: return jsonify({"error": str(e)}), 403
    rec = meta.get_file(file_id)
    if not rec: return jsonify({"error": "File not found"}), 404
    chunk_records = meta.get_chunk_locations(file_id)
    decrypted = []
    for r in chunk_records:
        key, iv  = meta.retrieve_key(file_id, r["chunk_index"])
        blob     = nc.fetch_chunk(file_id, r["chunk_index"], r["node_ids"])
        plain    = enc.decrypt_chunk(blob, key)
        if not chunker.verify_chunk(plain, r["chunk_hash"]):
            return jsonify({"error": f"Integrity check failed on chunk {r['chunk_index']}"}), 500
        decrypted.append(plain)
    return send_file(io.BytesIO(chunker.reassemble_bytes(decrypted)),
                     download_name=rec["file_name"], as_attachment=True,
                     mimetype="application/octet-stream")

@app.route("/api/files/<file_id>", methods=["DELETE"])
@login_required
def delete_file(file_id):
    try: require_permission(file_id, request.user_id, "delete")
    except PermissionError as e: return jsonify({"error": str(e)}), 403
    for r in meta.get_chunk_locations(file_id):
        nc.delete_chunk(file_id, r["chunk_index"], r["node_ids"])
    meta.delete_file_record(file_id)
    return jsonify({"message": "File deleted"})

@app.route("/api/files/<file_id>/share", methods=["POST"])
@login_required
def share_file(file_id):
    try: require_permission(file_id, request.user_id, "manage")
    except PermissionError as e: return jsonify({"error": str(e)}), 403
    data   = request.get_json()
    uname  = (data or {}).get("username")
    role   = (data or {}).get("role", "viewer")
    if not uname: return jsonify({"error": "username required"}), 400
    if role not in ("owner", "editor", "viewer"):
        return jsonify({"error": "role must be owner/editor/viewer"}), 400
    target = meta.get_user_by_username(uname)
    if not target: return jsonify({"error": "User not found"}), 404
    meta.grant_access(file_id, target["user_id"], role)
    return jsonify({"message": f"Granted {role} access to {uname}"})

# ── API: Nodes ─────────────────────────────────────────────────────────────
@app.route("/api/nodes/health", methods=["GET"])
@login_required
def node_health():
    # Use heartbeat cache — faster than pinging on every request
    status = get_status()
    return jsonify({"nodes": {k: v["alive"] for k, v in status.items()}})

# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    start_heartbeat()   # launch background heartbeat daemon
    print("=" * 55)
    print("  SecureVault Gateway + Heartbeat Monitor")
    print(f"  Dashboard →  http://localhost:{GATEWAY_PORT}")
    print("=" * 55)
    app.run(host=GATEWAY_HOST, port=GATEWAY_PORT, debug=False)
