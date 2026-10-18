"""
SecureVault — Start all 3 storage nodes in a single terminal.
Run: python scripts/start_nodes.py
     (Ctrl+C to shut all down)
"""

import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import NODES
from nodes.storage_node import StorageNode


def launch_node(cfg):
    storage_dir = os.path.join(
        os.path.dirname(__file__), "..", "data", "chunks", cfg["id"]
    )
    node = StorageNode(cfg["id"], cfg["host"], cfg["port"], storage_dir)
    node.start()


if __name__ == "__main__":
    print("Starting SecureVault storage cluster...")
    threads = []
    for node_cfg in NODES:
        t = threading.Thread(target=launch_node, args=(node_cfg,), daemon=True)
        t.start()
        threads.append(t)

    print(f"  {len(NODES)} nodes started. Press Ctrl+C to stop all.\n")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\nShutting down all nodes...")
