"""Policy Manager for AGENTGATE Core Security Module.

Loads trusted policy configuration from JSON and provides helper functions for
policy evaluation. All policy data is considered trusted and immutable for the
lifetime of the process – modifications must go through an authenticated admin
interface (outside the scope of this module).
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Set, Any, Optional

from models.policy import (
    PolicyConfig,
)

# Simple trusted user registry for demonstration purposes.
# In a real system this would be backed by a secure directory service.
_TRUSTED_USERS: Dict[str, str] = {
    "USER-001": "ADMINISTRATOR",
    "USER-101": "AUTHORIZED_USER",
    "USER-102": "AUTHORIZED_USER",
    "USER-201": "RESTRICTED_USER",
}

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "security_policies.json"

class PolicyLoadError(RuntimeError):
    """Raised when the policy configuration cannot be loaded or is invalid."""

def _load_policy_file() -> Dict[str, Any]:
    if not _CONFIG_PATH.is_file():
        raise PolicyLoadError(f"Policy file not found at {_CONFIG_PATH}")
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise PolicyLoadError(f"Failed to parse policy file: {exc}") from exc
    return data

# Load once at import time – fail closed if anything is wrong.
_raw_policy: Dict[str, Any] = _load_policy_file()
_policy = PolicyConfig.model_validate(_raw_policy)

def get_user_role(user_id: str) -> Optional[str]:
    """Return the trusted role for a given user identifier.

    Checks the dynamic UserManager (SQLite) first so newly registered or updated
    users are immediately recognized, then falls back to the static trusted registry.
    If the user is unknown in both, None is returned which leads to a BLOCK decision.
    """
    try:
        from auth.user_manager import default_user_manager
        user = default_user_manager.get_user_by_id(user_id)
        if user and user.get("role"):
            return user["role"]
    except Exception:
        pass

    return _TRUSTED_USERS.get(user_id)

def register_trusted_user(user_id: str, role: str) -> None:
    """Dynamically register or update an in-memory trusted user mapping."""
    _TRUSTED_USERS[user_id] = role

def get_allowed_operations_for_role(role: str) -> Set[str]:
    """Return the set of operation names allowed for the given role.

    If the role is not defined in the policy table, an empty set is returned.
    """
    role_cfg = _policy.roles.get(role)
    if not role_cfg:
        return set()
    return set(role_cfg.allowed_operations)

def get_allowed_roles_for_classification(classification: str) -> Set[str]:
    """Return roles that may access a resource of the given classification.
    """
    class_cfg = _policy.resource_classifications.get(classification)
    if not class_cfg:
        return set()
    return set(class_cfg.allowed_roles)

def is_recipient_authorized(recipient_id: str) -> bool:
    """Check whether a recipient identifier is listed as authorized.

    Checks the policy config's authorized_recipients list first, then queries
    the dynamic UserManager for users with authorized roles.
    """
    if recipient_id in _policy.recipient_authorizations.authorized_recipients:
        return True
    try:
        from auth.user_manager import default_user_manager
        user = default_user_manager.get_user_by_id(recipient_id)
        if user and user.get("role") in ("ADMINISTRATOR", "AUTHORIZED_USER"):
            return True
    except Exception:
        pass
    return False

def get_approval_required_operations() -> Dict[str, List[str]]:
    """Return a mapping of operation -> list of classifications that need approval.
    """
    return _policy.approval_required.approvals

def validate_policy_integrity() -> bool:
    """Run a lightweight sanity check on the loaded policy.

    Returns ``True`` if the policy appears consistent, otherwise ``False``.
    """
    for role_name, role_cfg in _policy.roles.items():
        if not role_cfg.allowed_operations:
            return False
    for class_name, class_cfg in _policy.resource_classifications.items():
        if not class_cfg.allowed_roles:
            return False
    return True
