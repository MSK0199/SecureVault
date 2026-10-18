"""
SecureVault — Chunker module
Splits any file into fixed-size binary chunks and reassembles them.

Flow (upload):
  file → split_file() → [chunk_0, chunk_1, …] → each chunk → encryptor

Flow (download):
  [chunk_0, chunk_1, …] (decrypted) → reassemble_file() → original file
"""

import os
import hashlib
from typing import Generator
from config import CHUNK_SIZE_BYTES


# ── Upload side ────────────────────────────────────────────────────────────

def split_file(file_path: str, chunk_size: int = CHUNK_SIZE_BYTES) -> Generator:
    """
    Read *file_path* and yield (chunk_index, chunk_bytes, chunk_hash) tuples.
    The last chunk may be smaller than chunk_size.

    Parameters
    ----------
    file_path  : path to the source file
    chunk_size : bytes per chunk (default from config, 4 MB)

    Yields
    ------
    (index: int, data: bytes, sha256_hex: str)
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    index = 0
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            sha256 = hashlib.sha256(chunk).hexdigest()
            yield index, chunk, sha256
            index += 1


def split_bytes(data: bytes, chunk_size: int = CHUNK_SIZE_BYTES) -> list[tuple]:
    """
    Same as split_file but operates on an in-memory bytes object.
    Used by the gateway when the upload arrives as a BytesIO stream.

    Returns list of (index, chunk_bytes, sha256_hex).
    """
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunk  = data[i : i + chunk_size]
        sha256 = hashlib.sha256(chunk).hexdigest()
        chunks.append((len(chunks), chunk, sha256))
    return chunks


def file_sha256(file_path: str) -> str:
    """Compute SHA-256 of the complete file (used for integrity verification)."""
    h = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


# ── Download side ──────────────────────────────────────────────────────────

def reassemble_file(chunks: list[bytes], output_path: str) -> str:
    """
    Concatenate decrypted chunk bytes in order and write to *output_path*.

    Parameters
    ----------
    chunks      : list of plaintext bytes in ascending chunk-index order
    output_path : destination path for the reassembled file

    Returns
    -------
    SHA-256 hex digest of the reassembled file (for integrity check).
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    h = hashlib.sha256()
    with open(output_path, "wb") as fh:
        for chunk in chunks:
            fh.write(chunk)
            h.update(chunk)
    return h.hexdigest()


def reassemble_bytes(chunks: list[bytes]) -> bytes:
    """Reassemble chunks into a single bytes object (used when serving downloads)."""
    return b"".join(chunks)


def verify_chunk(data: bytes, expected_sha256: str) -> bool:
    """Return True if SHA-256 of *data* matches *expected_sha256*."""
    return hashlib.sha256(data).hexdigest() == expected_sha256


if __name__ == "__main__":
    import tempfile, random

    # Create a 10 MB temp file filled with random bytes
    tmp = tempfile.mktemp(suffix=".bin")
    original_data = os.urandom(10 * 1024 * 1024)
    with open(tmp, "wb") as f:
        f.write(original_data)

    print(f"[chunker] Input file : {len(original_data):,} bytes")

    chunks_collected = []
    for idx, chunk, sha in split_file(tmp, chunk_size=4 * 1024 * 1024):
        print(f"  Chunk {idx}: {len(chunk):,} bytes  sha256={sha[:16]}…")
        assert verify_chunk(chunk, sha), f"Chunk {idx} hash mismatch!"
        chunks_collected.append(chunk)

    # Reassemble into a second temp file
    out = tmp + ".out"
    digest = reassemble_file(chunks_collected, out)
    with open(out, "rb") as f:
        recovered = f.read()

    assert recovered == original_data, "Reassembly FAILED — data mismatch"
    print(f"[chunker] Reassembly PASSED  ({len(chunks_collected)} chunks → {len(recovered):,} bytes)")

    os.remove(tmp)
    os.remove(out)
