"""
SecureVault — Role-Based Access Control (RBAC)

Roles:
  owner  → read, write, delete, manage
  editor → read, write
  viewer → read
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import ROLES
from core.metadata import get_role


def has_permission(file_id: str, user_id: str, action: str) -> bool:
    """
    Return True if *user_id* is permitted to perform *action* on *file_id*.

    Actions: "read" | "write" | "delete" | "manage"
    """
    role = get_role(file_id, user_id)
    if not role:
        return False
    return action in ROLES.get(role, set())


def require_permission(file_id: str, user_id: str, action: str):
    """Raise PermissionError if the user lacks the required action."""
    if not has_permission(file_id, user_id, action):
        role = get_role(file_id, user_id) or "none"
        raise PermissionError(
            f"User '{user_id}' with role '{role}' cannot '{action}' file '{file_id}'"
        )


def get_user_role(file_id: str, user_id: str) -> str:
    """Return the user's role string, or 'none' if no access."""
    return get_role(file_id, user_id) or "none"
