"""
SecureVault — Encryption module
Handles AES-256-GCM encrypt / decrypt for individual chunks.

Design decisions:
  • Each chunk gets a UNIQUE random key + IV — even if two chunks have
    identical plaintext, the ciphertexts differ completely.
  • The 16-byte GCM authentication tag is prepended to the ciphertext so
    a single blob can be stored / transmitted and verified on decryption.
  • Keys and IVs are NEVER written to storage nodes — they go to the
    metadata service (metadata.py) only.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32   # 256 bits
IV_BYTES  = 12   # 96-bit nonce — recommended for GCM


def generate_key() -> bytes:
    """Return a fresh cryptographically-random 256-bit AES key."""
    return os.urandom(KEY_BYTES)


def generate_iv() -> bytes:
    """Return a fresh cryptographically-random 96-bit GCM nonce."""
    return os.urandom(IV_BYTES)


def encrypt_chunk(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns
    -------
    ciphertext : bytes  — IV (12 B) + tag (16 B) + encrypted data
    key        : bytes  — 32-byte AES key (store in metadata, NOT on node)
    iv         : bytes  — 12-byte nonce  (also stored in metadata)
    """
    key = generate_key()
    iv  = generate_iv()
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + 16-byte tag appended automatically
    ciphertext = aesgcm.encrypt(iv, plaintext, associated_data=None)
    # Prepend IV so the blob is self-contained for transport
    blob = iv + ciphertext
    return blob, key, iv


def decrypt_chunk(blob: bytes, key: bytes) -> bytes:
    """
    Decrypt a blob produced by encrypt_chunk.

    Parameters
    ----------
    blob : bytes — IV (12 B) + ciphertext+tag from storage node
    key  : bytes — AES key retrieved from metadata service

    Returns
    -------
    Original plaintext bytes.

    Raises cryptography.exceptions.InvalidTag on tampered data.
    """
    iv         = blob[:IV_BYTES]
    ciphertext = blob[IV_BYTES:]
    aesgcm     = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, associated_data=None)


if __name__ == "__main__":
    # Quick self-test
    sample = b"Hello, SecureVault! " * 100
    blob, key, iv = encrypt_chunk(sample)
    recovered = decrypt_chunk(blob, key)
    assert recovered == sample, "Encryption round-trip FAILED"
    print(f"[encryptor] Self-test PASSED")
    print(f"  Plaintext  : {len(sample):,} bytes")
    print(f"  Ciphertext : {len(blob):,} bytes  (+ {len(blob)-len(sample)} bytes overhead)")
    print(f"  Key        : {key.hex()[:32]}...")
