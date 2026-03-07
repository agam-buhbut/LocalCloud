# LocalCloud - Server Database Layer
#
# SQLite schema and data access layer. Uses WAL mode for concurrent reads
# and BEGIN IMMEDIATE for write transactions to prevent race conditions.
# Schema is versioned for migration support.
# All access is serialized via threading.Lock (#3).

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Generator, Optional


# ──────────────────────────── Schema Version ────────────────────────────

SCHEMA_VERSION = 2

SCHEMA_SQL = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

-- User accounts
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    quota_bytes INTEGER NOT NULL DEFAULT 1073741824,  -- 1 GiB default
    used_bytes INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

-- Rate limiting tracking (with IP support #6)
CREATE TABLE IF NOT EXISTS login_attempts (
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    attempt_time REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time
    ON login_attempts(username, attempt_time);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts(ip_address, attempt_time);
CREATE INDEX IF NOT EXISTS idx_login_attempts_time
    ON login_attempts(attempt_time);

-- File metadata (server-side only — encrypted metadata is a blob)
CREATE TABLE IF NOT EXISTS files (
    file_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(user_id),
    filename TEXT NOT NULL,
    visibility INTEGER NOT NULL DEFAULT 0,  -- 0=private, 1=shared, 2=public
    total_chunks INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    encrypted_metadata BLOB NOT NULL,
    file_header BLOB NOT NULL,
    created_at REAL NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(user_id)
);
CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);

-- File sharing (who can access shared files)
CREATE TABLE IF NOT EXISTS file_shares (
    file_id TEXT NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    shared_with_id TEXT NOT NULL REFERENCES users(user_id),
    wrapped_keys BLOB NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (file_id, shared_with_id)
);

-- Staging uploads (in-progress uploads before finalization)
CREATE TABLE IF NOT EXISTS staging_uploads (
    upload_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(user_id),
    filename TEXT NOT NULL,
    expected_chunks INTEGER,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

-- Individual chunks in staging
CREATE TABLE IF NOT EXISTS staging_chunks (
    upload_id TEXT NOT NULL REFERENCES staging_uploads(upload_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    chunk_hash TEXT NOT NULL,
    chunk_size INTEGER NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (upload_id, chunk_index)
);
"""

# Migration from schema v1 to v2: add ip_address column and indexes
MIGRATION_V1_TO_V2 = """
ALTER TABLE login_attempts ADD COLUMN ip_address TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts(ip_address, attempt_time);
CREATE INDEX IF NOT EXISTS idx_login_attempts_time
    ON login_attempts(attempt_time);
"""


# ──────────────────────────── Database Class ────────────────────────────


class Database:
    """SQLite data access layer with WAL mode and atomic transactions.

    All operations are serialized via threading.Lock to prevent
    concurrent access on the single shared connection (#3).
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()

    def connect(self) -> None:
        """Open connection and initialize schema."""
        self._conn = sqlite3.connect(
            self.db_path,
            isolation_level=None,  # We manage transactions explicitly
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        # Enable WAL mode for concurrent reads
        self._conn.execute("PRAGMA journal_mode=WAL")
        # Foreign keys
        self._conn.execute("PRAGMA foreign_keys=ON")
        # Busy timeout (5 seconds)
        self._conn.execute("PRAGMA busy_timeout=5000")
        # Initialize schema
        self._init_schema()

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for write transactions using BEGIN IMMEDIATE.

        Guarantees atomic writes and prevents concurrent write races.
        Serialized via threading.Lock (#3).
        """
        assert self._conn is not None, "Database not connected"
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    @property
    def conn(self) -> sqlite3.Connection:
        """Get the connection for read operations.

        Callers MUST hold self._lock or be within a transaction() block.
        """
        assert self._conn is not None, "Database not connected"
        return self._conn

    def _init_schema(self) -> None:
        """Create tables if they don't exist and check schema version."""
        assert self._conn is not None
        self._conn.executescript(SCHEMA_SQL)
        # Check/set schema version
        row = self._conn.execute(
            "SELECT version FROM schema_version"
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
        elif row["version"] < SCHEMA_VERSION:
            # Run migrations
            if row["version"] == 1:
                try:
                    self._conn.executescript(MIGRATION_V1_TO_V2)
                except sqlite3.OperationalError:
                    pass  # Column may already exist
            self._conn.execute(
                "UPDATE schema_version SET version = ?",
                (SCHEMA_VERSION,),
            )
        elif row["version"] != SCHEMA_VERSION:
            raise RuntimeError(
                f"Schema version mismatch: expected {SCHEMA_VERSION}, "
                f"got {row['version']}"
            )

    # ──────────────────────────── User Operations ────────────────────────────

    def create_user(
        self,
        username: str,
        password_hash: str,
        quota_bytes: int,
    ) -> str:
        """Create a new user. Returns user_id."""
        user_id = str(uuid.uuid4())
        now = time.time()
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO users
                   (user_id, username, password_hash, quota_bytes,
                    used_bytes, is_active, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 0, 1, ?, ?)""",
                (user_id, username, password_hash, quota_bytes, now, now),
            )
        return user_id

    def get_user_by_username(self, username: str) -> Optional[dict]:
        """Look up a user by username. Returns None if not found."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> Optional[dict]:
        """Look up a user by user_id. Returns None if not found."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM users WHERE user_id = ?", (user_id,)
            ).fetchone()
            return dict(row) if row else None

    def disable_user(self, username: str) -> bool:
        """Disable a user account. Returns True if user existed."""
        with self.transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET is_active = 0, updated_at = ? WHERE username = ?",
                (time.time(), username),
            )
            return cursor.rowcount > 0

    def update_quota(self, username: str, quota_bytes: int) -> bool:
        """Update a user's quota. Returns True if user existed."""
        with self.transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET quota_bytes = ?, updated_at = ? WHERE username = ?",
                (quota_bytes, time.time(), username),
            )
            return cursor.rowcount > 0

    # ──────────────────────────── Rate Limiting ────────────────────────────

    def record_login_attempt(self, username: str, ip_address: str = "") -> None:
        """Record a login attempt for rate limiting (#6: includes IP)."""
        with self._lock:
            self.conn.execute(
                "INSERT INTO login_attempts (username, ip_address, attempt_time) "
                "VALUES (?, ?, ?)",
                (username, ip_address, time.time()),
            )

    def count_recent_attempts(
        self, username: str, window_seconds: int
    ) -> int:
        """Count login attempts within the rate limit window."""
        cutoff = time.time() - window_seconds
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) as cnt FROM login_attempts "
                "WHERE username = ? AND attempt_time > ?",
                (username, cutoff),
            ).fetchone()
            return row["cnt"] if row else 0

    def count_recent_attempts_by_ip(
        self, ip_address: str, window_seconds: int
    ) -> int:
        """Count login attempts from an IP within the rate limit window (#6)."""
        cutoff = time.time() - window_seconds
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) as cnt FROM login_attempts "
                "WHERE ip_address = ? AND attempt_time > ?",
                (ip_address, cutoff),
            ).fetchone()
            return row["cnt"] if row else 0

    def clear_login_attempts(self, username: str) -> None:
        """Clear login attempts for a user after successful login (#6)."""
        with self._lock:
            self.conn.execute(
                "DELETE FROM login_attempts WHERE username = ?",
                (username,),
            )

    def cleanup_old_attempts(self, window_seconds: int) -> None:
        """Remove login attempts older than the rate limit window."""
        cutoff = time.time() - window_seconds
        with self._lock:
            self.conn.execute(
                "DELETE FROM login_attempts WHERE attempt_time < ?", (cutoff,)
            )

    # ──────────────────────────── File Operations ────────────────────────────

    def create_file(
        self,
        file_id: str,
        owner_id: str,
        filename: str,
        visibility: int,
        total_chunks: int,
        total_bytes: int,
        encrypted_metadata: bytes,
        file_header: bytes,
    ) -> None:
        """Insert a finalized file record. Called within a transaction."""
        self.conn.execute(
            """INSERT INTO files
               (file_id, owner_id, filename, visibility, total_chunks,
                total_bytes, encrypted_metadata, file_header, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                file_id,
                owner_id,
                filename,
                visibility,
                total_chunks,
                total_bytes,
                encrypted_metadata,
                file_header,
                time.time(),
            ),
        )

    def get_file(self, file_id: str) -> Optional[dict]:
        """Get file metadata by file_id."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM files WHERE file_id = ?", (file_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_user_files(self, user_id: str) -> list[dict]:
        """List all files owned by or shared with a user."""
        with self._lock:
            rows = self.conn.execute(
                """SELECT f.* FROM files f
                   WHERE f.owner_id = ?
                   UNION
                   SELECT f.* FROM files f
                   JOIN file_shares fs ON f.file_id = fs.file_id
                   WHERE fs.shared_with_id = ?
                   UNION
                   SELECT f.* FROM files f
                   WHERE f.visibility = 2""",  # Public files
                (user_id, user_id),
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_file(self, file_id: str) -> Optional[int]:
        """Delete a file. Returns total_bytes for quota adjustment, or None."""
        row = self.conn.execute(
            "SELECT total_bytes FROM files WHERE file_id = ?", (file_id,)
        ).fetchone()
        if row is None:
            return None
        total_bytes = row["total_bytes"]
        self.conn.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
        return total_bytes

    # ──────────────────────────── Sharing ────────────────────────────

    def add_file_share(
        self,
        file_id: str,
        shared_with_id: str,
        wrapped_keys: bytes,
    ) -> None:
        """Share a file with another user."""
        self.conn.execute(
            """INSERT OR REPLACE INTO file_shares
               (file_id, shared_with_id, wrapped_keys, created_at)
               VALUES (?, ?, ?, ?)""",
            (file_id, shared_with_id, wrapped_keys, time.time()),
        )

    def get_file_shares(self, file_id: str) -> list[dict]:
        """Get all share records for a file."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM file_shares WHERE file_id = ?", (file_id,)
            ).fetchall()
            return [dict(row) for row in rows]

    def check_share_exists(self, file_id: str, user_id: str) -> bool:
        """Check if a user has been shared a file. O(1) via index (#12)."""
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM file_shares "
                "WHERE file_id = ? AND shared_with_id = ? LIMIT 1",
                (file_id, user_id),
            ).fetchone()
            return row is not None

    def get_wrapped_keys(
        self, file_id: str, user_id: str
    ) -> Optional[bytes]:
        """Get wrapped keys for a specific file and user."""
        with self._lock:
            row = self.conn.execute(
                "SELECT wrapped_keys FROM file_shares "
                "WHERE file_id = ? AND shared_with_id = ?",
                (file_id, user_id),
            ).fetchone()
            return row["wrapped_keys"] if row else None

    # ──────────────────────────── Staging ────────────────────────────

    def create_staging_upload(
        self,
        upload_id: str,
        owner_id: str,
        filename: str,
        expected_chunks: Optional[int],
        expiry_seconds: int,
    ) -> None:
        """Create a staging upload entry."""
        now = time.time()
        with self._lock:
            self.conn.execute(
                """INSERT INTO staging_uploads
                   (upload_id, owner_id, filename, expected_chunks,
                    created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    upload_id,
                    owner_id,
                    filename,
                    expected_chunks,
                    now,
                    now + expiry_seconds,
                ),
            )

    def get_staging_upload(self, upload_id: str) -> Optional[dict]:
        """Get a staging upload by upload_id."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM staging_uploads WHERE upload_id = ?",
                (upload_id,),
            ).fetchone()
            return dict(row) if row else None

    def add_staging_chunk(
        self,
        upload_id: str,
        chunk_index: int,
        chunk_hash: str,
        chunk_size: int,
    ) -> None:
        """Record a staged chunk."""
        with self._lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO staging_chunks
                   (upload_id, chunk_index, chunk_hash, chunk_size, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (upload_id, chunk_index, chunk_hash, chunk_size, time.time()),
            )

    def get_staging_chunks(self, upload_id: str) -> list[dict]:
        """Get all chunks for a staging upload, ordered by index."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM staging_chunks WHERE upload_id = ? "
                "ORDER BY chunk_index",
                (upload_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_staging_upload(self, upload_id: str) -> None:
        """Delete a staging upload and its chunks (via CASCADE)."""
        with self._lock:
            self.conn.execute(
                "DELETE FROM staging_uploads WHERE upload_id = ?",
                (upload_id,),
            )

    def cleanup_expired_staging(self) -> list[str]:
        """Delete expired staging uploads. Returns list of deleted upload_ids."""
        now = time.time()
        with self._lock:
            rows = self.conn.execute(
                "SELECT upload_id FROM staging_uploads WHERE expires_at < ?",
                (now,),
            ).fetchall()
            upload_ids = [row["upload_id"] for row in rows]
            if upload_ids:
                self.conn.execute(
                    "DELETE FROM staging_uploads WHERE expires_at < ?",
                    (now,),
                )
            return upload_ids

    # ──────────────────────────── Quota ────────────────────────────

    def get_user_usage(self, user_id: str) -> tuple[int, int]:
        """Get (used_bytes, quota_bytes) for a user."""
        row = self.conn.execute(
            "SELECT used_bytes, quota_bytes FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if row is None:
            raise ValueError("User not found")
        return row["used_bytes"], row["quota_bytes"]

    def increment_usage(self, user_id: str, bytes_added: int) -> None:
        """Atomically increment used_bytes. Must be called within a transaction."""
        self.conn.execute(
            "UPDATE users SET used_bytes = used_bytes + ?, updated_at = ? "
            "WHERE user_id = ?",
            (bytes_added, time.time(), user_id),
        )

    def decrement_usage(self, user_id: str, bytes_removed: int) -> None:
        """Atomically decrement used_bytes. Must be called within a transaction."""
        self.conn.execute(
            "UPDATE users SET used_bytes = MAX(0, used_bytes - ?), updated_at = ? "
            "WHERE user_id = ?",
            (bytes_removed, time.time(), user_id),
        )
