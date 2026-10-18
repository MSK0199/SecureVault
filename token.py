"""
SecureVault — JWT Token Module
Creates and validates signed JWT tokens for user sessions.
"""

import jwt
from datetime import datetime, timezone, timedelta
from config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_HRS


def create_token(user_id: str, username: str) -> str:
    """Generate a signed JWT for *user_id*."""
    payload = {
        "sub":      user_id,
        "username": username,
        "iat":      datetime.now(timezone.utc),
        "exp":      datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HRS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict | None:
    """
    Validate *token* and return the decoded payload, or None if invalid/expired.
    """
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def decode_token_unsafe(token: str) -> dict | None:
    """Decode without verification — only for debugging. Never use in prod."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None
