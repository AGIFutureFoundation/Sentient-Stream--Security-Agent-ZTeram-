"""
Sentinel Stream — RBAC (Role-Based Access Control).

Enterprise multi-tenancy + authorization for the API.

Roles:
  - viewer: read-only access to dashboard + alerts
  - analyst: viewer + can run NL queries, acknowledge alerts
  - responder: analyst + can trigger SOAR playbooks, close alerts
  - admin: full access including truncate, config, user management

Tenancy:
  - Each request carries an X-Tenant-ID header
  - All queries are automatically filtered by tenant_id
  - Events are tagged with tenant_id on ingest
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

API_KEY_HEADER = "X-API-Key"
TENANT_HEADER = "X-Tenant-ID"

# In production, back this with a database. For v0.4.0, file-backed.
USERS_FILE = os.environ.get("SENTINEL_RBAC_USERS_FILE", "")


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    RESPONDER = "responder"
    ADMIN = "admin"


ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.VIEWER: {
        "alerts.read", "events.read", "dashboard.view", "metrics.read",
    },
    Role.ANALYST: {
        "alerts.read", "events.read", "dashboard.view", "metrics.read",
        "alerts.acknowledge", "nl_query.run", "benchmark.read",
    },
    Role.RESPONDER: {
        "alerts.read", "events.read", "dashboard.view", "metrics.read",
        "alerts.acknowledge", "alerts.close", "nl_query.run", "benchmark.read",
        "soar.run", "belief_drift.trigger",
    },
    Role.ADMIN: {
        "alerts.read", "events.read", "dashboard.view", "metrics.read",
        "alerts.acknowledge", "alerts.close", "nl_query.run", "benchmark.read",
        "soar.run", "belief_drift.trigger",
        "admin.truncate", "admin.users", "admin.config",
    },
}


@dataclass
class User:
    """A user with API key + role + tenant."""
    user_id: str
    api_key_hash: str  # SHA-256 hash of the API key (never store plaintext)
    role: Role
    tenant_id: str
    name: str = ""
    email: str = ""
    created_at: float = field(default_factory=time.time)
    last_seen: float = 0.0
    active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "role": self.role.value,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "email": self.email,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "active": self.active,
        }


class RbacManager:
    """Manages users, API keys, and permission checks."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}  # user_id → User
        self._key_index: dict[str, str] = {}  # api_key_hash → user_id
        self._load_users()

    def create_user(self, user_id: str, role: Role, tenant_id: str, name: str = "", email: str = "") -> str:
        """Create a user. Returns the plaintext API key (shown once)."""
        api_key = self._generate_api_key()
        api_key_hash = self._hash_key(api_key)
        user = User(
            user_id=user_id,
            api_key_hash=api_key_hash,
            role=role,
            tenant_id=tenant_id,
            name=name,
            email=email,
        )
        self._users[user_id] = user
        self._key_index[api_key_hash] = user_id
        self._save_users()
        logger.info("Created user %s (role=%s, tenant=%s)", user_id, role.value, tenant_id)
        return api_key

    def revoke_user(self, user_id: str) -> bool:
        """Revoke a user's access."""
        user = self._users.pop(user_id, None)
        if user:
            self._key_index.pop(user.api_key_hash, None)
            self._save_users()
            logger.info("Revoked user %s", user_id)
            return True
        return False

    def authenticate(self, api_key: str) -> User | None:
        """Validate an API key. Returns the User if valid, None otherwise."""
        api_key_hash = self._hash_key(api_key)
        user_id = self._key_index.get(api_key_hash)
        if not user_id:
            return None
        user = self._users.get(user_id)
        if not user or not user.active:
            return None
        user.last_seen = time.time()
        return user

    def authorize(self, user: User, permission: str) -> bool:
        """Check if a user has a specific permission."""
        return permission in ROLE_PERMISSIONS.get(user.role, set())

    def list_users(self, tenant_id: str | None = None) -> list[User]:
        """List users, optionally filtered by tenant."""
        users = list(self._users.values())
        if tenant_id:
            users = [u for u in users if u.tenant_id == tenant_id]
        return users

    def _generate_api_key(self) -> str:
        """Generate a random API key."""
        return "ssk_" + secrets.token_urlsafe(32)

    def _hash_key(self, api_key: str) -> str:
        """SHA-256 hash of the API key with a pepper."""
        pepper = os.environ.get("SENTINEL_API_KEY_PEPPER", "sentinel-stream-v0.4")
        return hashlib.sha256((api_key + pepper).encode()).hexdigest()

    def _load_users(self) -> None:
        """Load users from file (if configured)."""
        if not USERS_FILE:
            return
        try:
            import json
            from pathlib import Path
            p = Path(USERS_FILE)
            if p.exists():
                data = json.loads(p.read_text())
                for uid, udata in data.items():
                    user = User(**udata)
                    self._users[uid] = user
                    self._key_index[user.api_key_hash] = uid
                logger.info("Loaded %s users from %s", len(self._users), USERS_FILE)
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to load users: %s", e)

    def _save_users(self) -> None:
        """Persist users to file (if configured)."""
        if not USERS_FILE:
            return
        try:
            import json
            from pathlib import Path
            p = Path(USERS_FILE)
            p.parent.mkdir(parents=True, exist_ok=True)
            data = {uid: {**asdict(u), "role": u.role.value} for uid, u in self._users.items()}
            p.write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to save users: %s", e)


# Singleton
_rbac: RbacManager | None = None


def get_rbac() -> RbacManager:
    global _rbac
    if _rbac is None:
        _rbac = RbacManager()
    return _rbac


# --- FastAPI dependency (for use in api.py) --------------------------------

def require_permission(permission: str):
    """FastAPI dependency that checks the request's API key has the permission.

    Usage in api.py:
        from sentinel.rbac import require_permission

        @app.post("/v1/admin/truncate")
        async def truncate(_: User = Depends(require_permission("admin.truncate"))):
            ...
    """
    from fastapi import Header, HTTPException

    def _check(
        x_api_key: str | None = Header(None, alias="X-API-Key"),
        x_tenant_id: str | None = Header(None, alias="X-Tenant-ID"),
    ) -> User:
        if not x_api_key:
            raise HTTPException(status_code=401, detail="X-API-Key header required")
        rbac = get_rbac()
        user = rbac.authenticate(x_api_key)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid API key")
        if x_tenant_id and user.tenant_id != x_tenant_id:
            raise HTTPException(status_code=403, detail="Tenant mismatch")
        if not rbac.authorize(user, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: requires '{permission}'. Role '{user.role.value}' insufficient.",
            )
        return user

    return _check
