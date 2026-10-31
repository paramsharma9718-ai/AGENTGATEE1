"""User Management and Authentication Module for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)

Features:
- Secure PBKDF2-HMAC-SHA256 password hashing with unique per-user salts.
- Role-based identity management bound to AGENTGATE security policies:
    * ADMINISTRATOR (Full access + approval authority)
    * AUTHORIZED_USER (Standard document operations)
    * RESTRICTED_USER (Restricted public documents only)
- Default trusted accounts seeded on initialization.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hash password using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    if not salt:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()
    return pw_hash, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify password against stored PBKDF2 hash."""
    computed_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)


class UserManager:
    """Thread-safe SQLite-backed user credentials and role manager."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = Path(__file__).resolve().parent.parent / "data"
            base_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(base_dir / "agentgate.db")
        else:
            self.db_path = db_path
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id TEXT UNIQUE NOT NULL,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        role TEXT NOT NULL,
                        full_name TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """)
                conn.commit()
            self._seed_default_users()

    def _seed_default_users(self) -> None:
        """Seed initial users matching AGENTGATE trusted roles."""
        defaults = [
            ("USER-001", "admin", "admin123", "ADMINISTRATOR", "Param Sharma (Admin)"),
            ("USER-101", "keshav", "keshav123", "AUTHORIZED_USER", "Keshav (Module 01)"),
            ("USER-102", "nihal", "nihal123", "AUTHORIZED_USER", "Nihal (Module 03)"),
            ("USER-201", "guest", "guest123", "RESTRICTED_USER", "Guest / Restricted"),
        ]

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                for uid, uname, pwd, role, fname in defaults:
                    cursor.execute("SELECT id FROM users WHERE username = ?", (uname,))
                    if not cursor.fetchone():
                        p_hash, salt = hash_password(pwd)
                        cursor.execute(
                            """
                            INSERT INTO users (user_id, username, password_hash, salt, role, full_name, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (uid, uname, p_hash, salt, role, fname, utc_now_iso()),
                        )
                conn.commit()

    def register_user(
        self,
        username: str,
        password: str,
        role: str = "AUTHORIZED_USER",
        full_name: str = "",
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Register a new user account with secure password hashing."""
        uname = username.strip().lower()
        if not uname or len(uname) < 3:
            return False, "Username must be at least 3 characters.", None

        if not password or len(password) < 6:
            return False, "Password must be at least 6 characters.", None

        valid_roles = ["ADMINISTRATOR", "AUTHORIZED_USER", "RESTRICTED_USER"]
        if role not in valid_roles:
            return False, f"Invalid role. Must be one of {valid_roles}", None

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE username = ?", (uname,))
                if cursor.fetchone():
                    return False, f"Username '{uname}' already exists.", None

                # Generate user_id
                cursor.execute("SELECT count(*) as count FROM users")
                cnt = cursor.fetchone()["count"]
                user_id = f"USER-{300 + cnt}"

                p_hash, salt = hash_password(password)
                now_str = utc_now_iso()

                cursor.execute(
                    """
                    INSERT INTO users (user_id, username, password_hash, salt, role, full_name, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, uname, p_hash, salt, role, full_name or uname.title(), now_str),
                )
                conn.commit()

                user_dict = {
                    "user_id": user_id,
                    "username": uname,
                    "role": role,
                    "full_name": full_name or uname.title(),
                    "created_at": now_str,
                }
                return True, "Registration successful!", user_dict

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Verify user credentials and return user profile if valid."""
        uname = username.strip().lower()
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (uname,))
                row = cursor.fetchone()
                if not row:
                    return None

                row_dict = dict(row)
                if verify_password(password, row_dict["password_hash"], row_dict["salt"]):
                    return {
                        "user_id": row_dict["user_id"],
                        "username": row_dict["username"],
                        "role": row_dict["role"],
                        "full_name": row_dict["full_name"],
                        "created_at": row_dict["created_at"],
                    }
                return None

    def list_users(self) -> List[Dict[str, Any]]:
        """Return all registered users."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT user_id, username, role, full_name, created_at FROM users ORDER BY id ASC")
                return [dict(row) for row in cursor.fetchall()]

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT user_id, username, role, full_name, created_at FROM users WHERE user_id = ?", (user_id,))
                row = cursor.fetchone()
                return dict(row) if row else None


# Default singleton instance
default_user_manager = UserManager()
