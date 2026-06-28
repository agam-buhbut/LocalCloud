# LocalCloud - Server Database Layer
#
# SQLite schema and data access layer. Uses WAL mode for concurrent reads
# and BEGIN IMMEDIATE for write transactions to prevent race conditions.
# Schema is versioned for migration support.
# All access is serialized via threading.Lock (#3).

from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager, suppress

# ──────────────────────────── Schema Version ────────────────────────────

SCHEMA_VERSION = 6

# Grace window for finalizing-flagged rows that have already passed
# their normal expiry. A finalize handler that crashed mid-commit
# leaves finalizing=1; without this, cleanup would skip the row
# forever (cleanup_expired_staging filters finalizing=0). After this
# many seconds past expiry, cleanup reclaims it. Long enough that no
# legitimate finalize would still be running. (Round-2 H4)
_FINALIZING_GRACE_SECONDS = 3600

# SCHEMA_SQL creates TABLES ONLY — every CREATE INDEX lives in
# SCHEMA_INDEXES_SQL and is applied AFTER migrations (see _init_schema).
# Splitting them is what fixes MIG-1: on an old (<v6) database the table
# already exists (CREATE TABLE IF NOT EXISTS is a no-op) but is missing
# columns the migrations have not added yet; if the index that references
# such a column (e.g. login_attempts.ip_address, staging_uploads.finalizing)
# were created here, SQLite raises "no such column" before migrations run.
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
    -- Monotonic counter used to revoke all outstanding session tokens
    -- for this user. Tokens embed the value at issue time; any bump
    -- invalidates every previously-issued token immediately.
    session_version INTEGER NOT NULL DEFAULT 1,
    -- Long-term Ed25519 identity public key (32 bytes). Empty until the
    -- user registers a key; clients use this for pinned signature
    -- verification of files owned by this user (H17).
    ed25519_pubkey BLOB NOT NULL DEFAULT x'',
    -- Long-term X25519 key-agreement public key (32 bytes). Empty until the
    -- user enrolls. Used by sharers/publishers to wrap file keys to this
    -- user (2C / FEAT-1).
    x25519_pubkey BLOB NOT NULL DEFAULT x'',
    -- Ed25519 self-signature (64 bytes) over enroll_signing_input(x25519_pubkey).
    -- Lets a sharer who pinned this user's Ed25519 fingerprint verify the
    -- X25519 key transitively. Empty until enrollment (2C / FEAT-1).
    x25519_self_sig BLOB NOT NULL DEFAULT x'',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

-- Rate limiting tracking (with IP support #6)
CREATE TABLE IF NOT EXISTS login_attempts (
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    attempt_time REAL NOT NULL
);

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
    -- Set to 1 by the finalize handler inside its transaction so the
    -- background cleanup task will skip this row mid-finalize (H19).
    finalizing INTEGER NOT NULL DEFAULT 0,
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

# All indexes, applied unconditionally AFTER tables + migrations on every
# connect (every statement is IF NOT EXISTS, so it is idempotent for both a
# fresh install and an upgraded DB once the referenced columns exist). This
# is the single source of truth for indexes — migrations no longer create
# any. (MIG-1)
SCHEMA_INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time
    ON login_attempts(username, attempt_time);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts(ip_address, attempt_time);
CREATE INDEX IF NOT EXISTS idx_login_attempts_time
    ON login_attempts(attempt_time);
-- Index `visibility` so the public-file branch of list_user_files
-- doesn't scan the whole files table. (Round-3 perf #2)
CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
CREATE INDEX IF NOT EXISTS idx_files_visibility
    ON files(visibility, created_at DESC);
-- Index lookups by recipient so list_user_files's shared-with branch
-- doesn't scan all shares to find this user's rows. (Round-3 perf #2)
CREATE INDEX IF NOT EXISTS idx_file_shares_user
    ON file_shares(shared_with_id);
-- Index staging owner_id for get_total_staging_bytes / count_open_uploads;
-- without it those hot-path queries do a full table scan plus join.
CREATE INDEX IF NOT EXISTS idx_staging_uploads_owner
    ON staging_uploads(owner_id, finalizing, expires_at);
"""

# Migrations are lists of single ALTER statements applied one at a time by
# _apply_idempotent_alters, each tolerating ONLY "duplicate column name".
# Per-statement application (rather than one executescript of the whole
# block) is what fixes MIG-2: if a crash already applied ALTER #1, on the
# next connect #1 re-raises duplicate-column (swallowed) and #2 still runs.
# Index creation is no longer done here — it is centralised in
# SCHEMA_INDEXES_SQL and applied unconditionally after migrations (MIG-1).

# v1 -> v2: add ip_address column to login_attempts.
MIGRATION_V1_TO_V2: list[str] = [
    "ALTER TABLE login_attempts ADD COLUMN ip_address TEXT NOT NULL DEFAULT ''",
]

# v2 -> v3: add session_version column for token revocation.
MIGRATION_V2_TO_V3: list[str] = [
    "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1",
]

# v3 -> v4:
#   * `finalizing` flag on staging_uploads — set during the finalize
#     transaction so the periodic cleanup task does not race finalize (H19).
#   * `ed25519_pubkey` BLOB on users — owner identity key returned with file
#     metadata for pinned signature verification (H17).
MIGRATION_V3_TO_V4: list[str] = [
    "ALTER TABLE staging_uploads ADD COLUMN finalizing INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN ed25519_pubkey BLOB NOT NULL DEFAULT x''",
]

# v4 -> v5 was index-only; those indexes now live in SCHEMA_INDEXES_SQL, so
# the step is a pure version bump with no ALTERs (handled in _run_migrations).

# v5 -> v6: add the user's long-term X25519 key-agreement public key plus its
# Ed25519 self-signature (2C / FEAT-1). Existing v5 rows migrate with empty
# key + empty self-sig — i.e. "not enrolled".
MIGRATION_V5_TO_V6: list[str] = [
    "ALTER TABLE users ADD COLUMN x25519_pubkey BLOB NOT NULL DEFAULT x''",
    "ALTER TABLE users ADD COLUMN x25519_self_sig BLOB NOT NULL DEFAULT x''",
]


def _is_duplicate_column_error(exc: sqlite3.OperationalError) -> bool:
    """Return True iff SQLite reported 'duplicate column name'.

    Migration scripts are idempotent only for this specific failure —
    any other OperationalError (locked DB, syntax, etc.) must propagate.
    """
    message = str(exc).lower()
    return "duplicate column name" in message


# ──────────────────────────── Database Class ────────────────────────────


class Database:
    """SQLite data access layer with WAL mode and atomic transactions.

    All operations are serialized via threading.Lock to prevent
    concurrent access on the single shared connection (#3).
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None
        # Reentrant so a read method (e.g. get_user_usage) can be called
        # from inside a transaction() block without deadlocking. Earlier
        # code skipped the lock on non-transaction callers, which caused
        # torn reads under concurrency on the shared connection. With
        # RLock we can acquire it unconditionally on every read.
        # (Round-2 C1)
        self._lock = threading.RLock()

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
        # PERF (4B-a): under WAL, synchronous=NORMAL is crash-safe — the
        # database cannot corrupt; the only exposure is losing the *last*
        # committed transaction on an OS crash / power loss (a checkpoint
        # still syncs the WAL into the main db). FULL would additionally
        # fsync on every commit. We keep durability of file *bytes* (the
        # per-chunk fsync in storage.py is unchanged); this only relaxes the
        # per-commit fsync of the metadata WAL. See docs/benchmarks.md (4B).
        self._conn.execute("PRAGMA synchronous=NORMAL")
        # Initialize schema
        self._init_schema()
        # L-1 (pentest 2026-06-22): SQLite creates the DB + -wal/-shm with the
        # process umask (often 0644). The DB holds password hashes and all
        # server-side metadata; tighten to 0600. Defense in depth — the 0700
        # data dir is the primary gate, but the file should not rely on it.
        for _suffix in ("", "-wal", "-shm"):
            with suppress(OSError):  # :memory:, sidecar absent, or unsupported fs
                os.chmod(self.db_path + _suffix, 0o600)

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

    def _apply_idempotent_alters(self, statements: list[str]) -> None:
        """Apply migration ALTERs one statement at a time (MIG-2).

        Each statement is run individually so a crash that already applied
        an earlier ALTER does not prevent a later one from running on the
        next connect: the already-applied one re-raises "duplicate column
        name" (swallowed here), and the remaining statements still execute.
        Every OTHER OperationalError (locked DB, syntax, etc.) propagates —
        we never silently swallow a real failure.
        """
        assert self._conn is not None
        for statement in statements:
            try:
                self._conn.execute(statement)
            except sqlite3.OperationalError as exc:
                if not _is_duplicate_column_error(exc):
                    raise

    def _run_migrations(self, current: int) -> None:
        """Upgrade an existing DB from ``current`` to ``SCHEMA_VERSION``.

        Runs only the steps newer than ``current``, in order. v4 -> v5 was
        index-only (now handled by SCHEMA_INDEXES_SQL), so it is a bare
        version bump with no ALTERs.
        """
        if current < 2:
            self._apply_idempotent_alters(MIGRATION_V1_TO_V2)
            current = 2
        if current < 3:
            self._apply_idempotent_alters(MIGRATION_V2_TO_V3)
            current = 3
        if current < 4:
            self._apply_idempotent_alters(MIGRATION_V3_TO_V4)
            current = 4
        if current < 5:
            current = 5
        if current < 6:
            self._apply_idempotent_alters(MIGRATION_V5_TO_V6)
            current = 6

    def _init_schema(self) -> None:
        """Create tables, run migrations, then (re)create indexes.

        Ordering is load-bearing (MIG-1): tables first, then any pending
        column-adding migrations, and ONLY THEN the indexes — so a CREATE
        INDEX can never reference a column an old (<v6) table has not yet
        gained via ALTER.
        """
        assert self._conn is not None
        self._conn.executescript(SCHEMA_SQL)
        # Check/set schema version.
        row = self._conn.execute("SELECT version FROM schema_version").fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
        elif row["version"] < SCHEMA_VERSION:
            self._run_migrations(row["version"])
            self._conn.execute(
                "UPDATE schema_version SET version = ?",
                (SCHEMA_VERSION,),
            )
        elif row["version"] != SCHEMA_VERSION:
            raise RuntimeError(
                f"Schema version mismatch: expected {SCHEMA_VERSION}, "
                f"got {row['version']}"
            )
        # Indexes are created unconditionally now that every referenced
        # column exists (fresh install or post-migration). All IF NOT
        # EXISTS, so this is a cheap idempotent no-op on subsequent connects.
        self._conn.executescript(SCHEMA_INDEXES_SQL)

    # ──────────────────────────── User Operations ────────────────────────────

    def create_user(
        self,
        username: str,
        password_hash: str,
        quota_bytes: int,
        ed25519_pubkey: bytes = b"",
    ) -> str:
        """Create a new user. Returns user_id.

        Args:
            ed25519_pubkey: Optional long-term Ed25519 identity public
                key (32 bytes). Defaults to empty; clients may register
                it later through a separate flow.
        """
        user_id = str(uuid.uuid4())
        now = time.time()
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO users
                   (user_id, username, password_hash, quota_bytes,
                    used_bytes, is_active, ed25519_pubkey,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, 0, 1, ?, ?, ?)""",
                (
                    user_id,
                    username,
                    password_hash,
                    quota_bytes,
                    ed25519_pubkey,
                    now,
                    now,
                ),
            )
        return user_id

    def get_user_by_username(self, username: str) -> dict | None:
        """Look up a user by username. Returns None if not found."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> dict | None:
        """Look up a user by user_id. Returns None if not found."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM users WHERE user_id = ?", (user_id,)
            ).fetchone()
            return dict(row) if row else None

    def disable_user(self, username: str) -> bool:
        """Disable a user account AND bump session_version atomically.

        Bumping session_version invalidates every outstanding token for
        the user so a disabled user's existing sessions are revoked the
        moment the next request hits ``require_auth`` (the version check
        rejects the now-stale token).

        Returns True if the user existed.
        """
        now = time.time()
        with self.transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET is_active = 0, "
                "session_version = session_version + 1, "
                "updated_at = ? WHERE username = ?",
                (now, username),
            )
            return cursor.rowcount > 0

    def get_user_status(self, user_id: str) -> tuple[int, bool] | None:
        """Return ``(session_version, is_active)`` for a user, or None.

        Combines the two reads ``require_auth`` needs into a single
        query so we don't pay two ``threading.Lock`` acquisitions and
        two thread bounces per authenticated request.
        """
        with self._lock:
            row = self.conn.execute(
                "SELECT session_version, is_active " "FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            if row is None:
                return None
            return int(row["session_version"]), bool(row["is_active"])

    def bump_session_version(self, username: str) -> bool:
        """Invalidate all outstanding tokens for a user. Returns True if user existed."""
        with self.transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET session_version = session_version + 1, "
                "updated_at = ? WHERE username = ?",
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

    # ──────────────────────────── X25519 Enrollment ────────────────────────────

    def set_user_x25519(
        self,
        username: str,
        x25519_pubkey: bytes,
        self_sig: bytes,
    ) -> bool:
        """Store a user's X25519 public key and its Ed25519 self-signature.

        Enrollment for 2C key delivery. The caller is responsible for
        canonicalizing ``username`` and for verifying ``self_sig`` against
        the user's Ed25519 key before calling — this layer only persists.

        Args:
            username: Canonical username (caller-canonicalized, consistent
                with the other user lookups in this layer).
            x25519_pubkey: 32-byte X25519 key-agreement public key.
            self_sig: 64-byte Ed25519 self-signature over the
                domain-separated, username-bound enroll input.

        Returns:
            True if the user existed (a row was updated).
        """
        with self.transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET x25519_pubkey = ?, x25519_self_sig = ?, "
                "updated_at = ? WHERE username = ?",
                (x25519_pubkey, self_sig, time.time(), username),
            )
            return cursor.rowcount > 0

    def get_user_x25519(self, username: str) -> tuple[bytes, bytes] | None:
        """Return ``(x25519_pubkey, self_sig)`` for an enrolled user.

        Returns None when the user is unknown OR has not enrolled an
        X25519 key (the columns are still empty). Note: the HTTP directory
        layer — NOT this method — is responsible for the uniform,
        non-enumerating response; here None genuinely means "no usable key".

        Args:
            username: Canonical username (caller-canonicalized).
        """
        with self._lock:
            row = self.conn.execute(
                "SELECT x25519_pubkey, x25519_self_sig FROM users "
                "WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                return None
            pubkey = bytes(row["x25519_pubkey"] or b"")
            sig = bytes(row["x25519_self_sig"] or b"")
            if not pubkey or not sig:
                return None
            return pubkey, sig

    def list_enrolled_users(self) -> list[dict]:
        """List users who have enrolled an X25519 key (non-empty columns).

        Backs the publish-fanout directory. Each entry carries the
        username plus the public Ed25519 / X25519 keys and the X25519
        self-signature so a caller can verify the self-sig before wrapping.
        All returned fields are public by definition.
        """
        with self._lock:
            rows = self.conn.execute(
                "SELECT username, ed25519_pubkey, x25519_pubkey, "
                "x25519_self_sig FROM users "
                "WHERE x25519_pubkey != x'' AND x25519_self_sig != x'' "
                "ORDER BY username",
            ).fetchall()
            return [
                {
                    "username": row["username"],
                    "ed25519_pubkey": bytes(row["ed25519_pubkey"] or b""),
                    "x25519_pubkey": bytes(row["x25519_pubkey"] or b""),
                    "x25519_self_sig": bytes(row["x25519_self_sig"] or b""),
                }
                for row in rows
            ]

    # ──────────────────────────── Rate Limiting ────────────────────────────

    def record_login_attempt(
        self,
        username: str,
        ip_address: str = "",
        *,
        max_rows_per_window: int | None = None,
        window_seconds: int | None = None,
    ) -> bool:
        """Record a login attempt for rate limiting (#6: includes IP).

        SEC-M4: when both ``max_rows_per_window`` and ``window_seconds``
        are provided AND ``ip_address`` is non-empty, the insert is
        skipped once this peer already has ``max_rows_per_window`` rows
        within the trailing ``window_seconds``. This bounds login_attempts
        row growth from a single peer flooding distinct (synthetic)
        usernames — each distinct username would otherwise author its own
        row indefinitely. The count + insert run under the same lock so
        the cap is enforced atomically on the shared connection.

        The cap is a storage-layer defense only: it does NOT change any
        auth outcome (the in-memory composite limiter is authoritative
        for lockout) and the count/insert is unconditional with respect
        to whether the attempt succeeded or failed — callers record only
        on failure exactly as before.

        Args:
            username: Canonical username the attempt targeted.
            ip_address: Peer identity (WireGuard source IP). Empty string
                disables the cap — there is no peer to attribute rows to.
            max_rows_per_window: Maximum rows a single peer may hold in
                the window before further inserts are dropped. ``None``
                (the default) preserves the legacy unconditional insert.
            window_seconds: Trailing window for the per-peer row count.

        Returns:
            True if a row was inserted, False if the per-peer cap was hit.
        """
        with self._lock:
            cap_active = (
                max_rows_per_window is not None
                and window_seconds is not None
                and bool(ip_address)
            )
            if cap_active:
                # Narrow: re-asserted for the type checker; cap_active
                # already guarantees these are not None.
                assert max_rows_per_window is not None
                assert window_seconds is not None
                cutoff = time.time() - window_seconds
                row = self.conn.execute(
                    "SELECT COUNT(*) AS cnt FROM login_attempts "
                    "WHERE ip_address = ? AND attempt_time > ?",
                    (ip_address, cutoff),
                ).fetchone()
                if row is not None and row["cnt"] >= max_rows_per_window:
                    return False
            self.conn.execute(
                "INSERT INTO login_attempts (username, ip_address, attempt_time) "
                "VALUES (?, ?, ?)",
                (username, ip_address, time.time()),
            )
            return True

    def count_recent_attempts(
        self,
        username: str,
        window_seconds: int,
        ip_address: str | None = None,
    ) -> int:
        """Count login attempts for a username within the rate-limit window.

        Args:
            username: Canonical username the attempts targeted.
            window_seconds: Trailing window (seconds) to count within.
            ip_address: When provided, additionally scope the count to this
                peer (``AND ip_address = ?``) so the legacy per-username gate
                matches the composite limiter's per-peer blast radius — a
                flood from one peer can no longer lock the username out from
                another peer (AUTH-1). When ``None`` (the default) the
                behaviour is exactly the legacy username-only count.
        """
        cutoff = time.time() - window_seconds
        with self._lock:
            if ip_address is None:
                row = self.conn.execute(
                    "SELECT COUNT(*) as cnt FROM login_attempts "
                    "WHERE username = ? AND attempt_time > ?",
                    (username, cutoff),
                ).fetchone()
            else:
                row = self.conn.execute(
                    "SELECT COUNT(*) as cnt FROM login_attempts "
                    "WHERE username = ? AND ip_address = ? AND attempt_time > ?",
                    (username, ip_address, cutoff),
                ).fetchone()
            return row["cnt"] if row else 0

    def count_recent_attempts_by_ip(self, ip_address: str, window_seconds: int) -> int:
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

    def get_file(self, file_id: str) -> dict | None:
        """Get file metadata by file_id."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM files WHERE file_id = ?", (file_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_owner_ed25519_pubkey(self, file_id: str) -> bytes | None:
        """Return the file owner's Ed25519 identity public key (H17).

        Returns the raw bytes (possibly empty if the owner has not
        registered a key), or None if the file does not exist.
        """
        with self._lock:
            row = self.conn.execute(
                "SELECT u.ed25519_pubkey "
                "FROM files f JOIN users u ON u.user_id = f.owner_id "
                "WHERE f.file_id = ?",
                (file_id,),
            ).fetchone()
            if row is None:
                return None
            pubkey = row["ed25519_pubkey"]
            # Older rows may surface as None even with the NOT NULL
            # default — normalise to empty bytes.
            return bytes(pubkey) if pubkey is not None else b""

    def list_user_files(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """List files owned by, shared with, or publicly visible to the user.

        Paginated to bound result-set size (#H9). Selects only the
        columns the caller needs — previously the UNION returned every
        column including ``encrypted_metadata`` and ``file_header`` BLOBs
        that the route handler immediately discarded, costing significant
        I/O on large public corpora.
        """
        if limit < 1 or limit > 200 or offset < 0:
            raise ValueError("limit/offset out of range")
        # PERF (4D): the previous query UNION'd the three visibility branches
        # and then sorted the whole result, building two TEMP B-trees for the
        # UNION dedup and one for the ORDER BY over the ENTIRE matching set —
        # so first-page latency tracked total public-file count (measured 0.86
        # ms @200 files -> 17.6 ms @5000; see docs/benchmarks.md).
        #
        # Since we only need one page, the global top (offset+limit) rows are
        # contained in the union of each branch's own top (offset+limit) rows
        # (a row globally in the top-N is at worst at rank N within its own
        # branch; dedup cannot push a distinct row past that). So we cap each
        # branch with ORDER BY created_at DESC LIMIT (offset+limit): the public
        # branch is served directly by idx_files_visibility(visibility,
        # created_at DESC) and stops after `cap` rows instead of materializing
        # the whole corpus. UNION ALL then preserves duplicates, GROUP BY
        # file_id dedups (every column is identical across branches for the
        # same file, so the bare-column pick is deterministic), and the outer
        # sort runs over at most 3*cap rows rather than the full corpus.
        inner_cap = limit + offset
        with self._lock:
            rows = self.conn.execute(
                """SELECT file_id, owner_id, filename, visibility,
                          total_chunks, total_bytes, created_at FROM (
                    SELECT * FROM (
                        SELECT f.file_id, f.owner_id, f.filename, f.visibility,
                               f.total_chunks, f.total_bytes, f.created_at
                        FROM files f WHERE f.owner_id = ?
                        ORDER BY f.created_at DESC LIMIT ?
                    )
                    UNION ALL
                    SELECT * FROM (
                        SELECT f.file_id, f.owner_id, f.filename, f.visibility,
                               f.total_chunks, f.total_bytes, f.created_at
                        FROM files f
                        JOIN file_shares fs ON f.file_id = fs.file_id
                        WHERE fs.shared_with_id = ?
                        ORDER BY f.created_at DESC LIMIT ?
                    )
                    UNION ALL
                    SELECT * FROM (
                        SELECT f.file_id, f.owner_id, f.filename, f.visibility,
                               f.total_chunks, f.total_bytes, f.created_at
                        FROM files f WHERE f.visibility = 2
                        ORDER BY f.created_at DESC LIMIT ?
                    )
                )
                GROUP BY file_id
                ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (user_id, inner_cap, user_id, inner_cap, inner_cap, limit, offset),
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_file(self, file_id: str) -> int | None:
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

    def remove_file_share(
        self,
        file_id: str,
        shared_with_id: str,
    ) -> bool:
        """Remove a file share. Returns True if a row was deleted.

        Server-side revocation only — the recipient may already have
        downloaded and decrypted the file; this endpoint blocks future
        access to the wrapped keys from the server. To force key
        rotation, the owner must re-upload the file under a new
        file_key. Caller must wrap in a transaction.
        """
        cursor = self.conn.execute(
            "DELETE FROM file_shares " "WHERE file_id = ? AND shared_with_id = ?",
            (file_id, shared_with_id),
        )
        return cursor.rowcount > 0

    def count_file_shares(self, file_id: str) -> int:
        """Return the number of share rows for a file."""
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS cnt FROM file_shares WHERE file_id = ?",
                (file_id,),
            ).fetchone()
            return int(row["cnt"]) if row else 0

    def check_share_exists(self, file_id: str, user_id: str) -> bool:
        """Check if a user has been shared a file. O(1) via index (#12)."""
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM file_shares "
                "WHERE file_id = ? AND shared_with_id = ? LIMIT 1",
                (file_id, user_id),
            ).fetchone()
            return row is not None

    def get_wrapped_keys(self, file_id: str, user_id: str) -> bytes | None:
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
        expected_chunks: int | None,
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

    def try_create_staging_upload(
        self,
        upload_id: str,
        owner_id: str,
        filename: str,
        expected_chunks: int | None,
        expiry_seconds: int,
        max_open_uploads: int,
    ) -> bool:
        """Atomically create a staging upload iff the user is under the cap.

        Counts the user's open (non-expired, non-finalizing) uploads and
        inserts the new row in ONE write transaction (BEGIN IMMEDIATE), so
        two concurrent inits at the cap cannot both pass a snapshot count and
        then both insert past ``max_open_uploads`` (STG-4). Mirrors the chunk
        check-and-insert pattern.

        Returns:
            True if the row was created, False if the user is already at
            ``max_open_uploads`` open uploads.
        """
        now = time.time()
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM staging_uploads "
                "WHERE owner_id = ? AND expires_at >= ? AND finalizing = 0",
                (owner_id, now),
            ).fetchone()
            open_count = int(row["cnt"]) if row else 0
            if open_count >= max_open_uploads:
                return False
            conn.execute(
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
            return True

    def reclaim_expired_staging_for_user(self, owner_id: str) -> list[str]:
        """Delete a user's expired, non-finalizing staging rows; return ids.

        Called synchronously at upload_init (STG-5) so a just-expired
        upload's bytes/rows are reclaimed for this user before the new
        upload's caps are evaluated, instead of lingering cap-invisible
        (excluded by ``get_total_staging_bytes``/``count_open_uploads``)
        until the periodic GC runs. ``finalizing = 1`` rows are left to the
        finalize path / grace sweep. The caller is responsible for removing
        the returned uploads' on-disk staging directories.
        """
        now = time.time()
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT upload_id FROM staging_uploads "
                "WHERE owner_id = ? AND expires_at < ? AND finalizing = 0",
                (owner_id, now),
            ).fetchall()
            upload_ids = [row["upload_id"] for row in rows]
            if upload_ids:
                conn.execute(
                    "DELETE FROM staging_uploads "
                    "WHERE owner_id = ? AND expires_at < ? AND finalizing = 0",
                    (owner_id, now),
                )
            return upload_ids

    def get_staging_upload(self, upload_id: str) -> dict | None:
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

    def get_staging_chunk_size(self, upload_id: str, chunk_index: int) -> int | None:
        """Return the recorded ``chunk_size`` for a staged chunk, or None.

        Backs the re-upload delta accounting (STG-3): when a client re-POSTs
        an index it already staged, only the size *difference* against the
        existing row should count toward quota, otherwise the prior row is
        double-counted by ``get_total_staging_bytes`` (which already includes
        it). Returns None when no row exists for ``(upload_id, chunk_index)``.
        """
        with self._lock:
            row = self.conn.execute(
                "SELECT chunk_size FROM staging_chunks "
                "WHERE upload_id = ? AND chunk_index = ?",
                (upload_id, chunk_index),
            ).fetchone()
            return int(row["chunk_size"]) if row else None

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
        """Delete expired staging uploads. Returns list of deleted upload_ids.

        H19: Skips rows with finalizing = 1 so the periodic cleanup task
        cannot CASCADE-delete chunks out from under an in-flight finalize
        transaction.

        Safety net: ALSO reclaims rows that have been finalizing=1 for
        more than `_FINALIZING_GRACE_SECONDS`. A finalize handler that
        crashed mid-commit otherwise leaves the row stuck forever (the
        non-cleanup path also doesn't count it against quota, so it's a
        slow row leak rather than disk leak). (Round-2 H4)
        """
        now = time.time()
        grace_cutoff = now - _FINALIZING_GRACE_SECONDS
        with self._lock:
            rows = self.conn.execute(
                "SELECT upload_id FROM staging_uploads "
                "WHERE (expires_at < ? AND finalizing = 0) "
                "   OR (finalizing = 1 AND expires_at < ?)",
                (now, grace_cutoff),
            ).fetchall()
            upload_ids = [row["upload_id"] for row in rows]
            if upload_ids:
                # Use the same predicate on DELETE so a row that flipped
                # to finalizing=1 between SELECT and DELETE in the
                # non-finalizing branch is preserved.
                self.conn.execute(
                    "DELETE FROM staging_uploads "
                    "WHERE (expires_at < ? AND finalizing = 0) "
                    "   OR (finalizing = 1 AND expires_at < ?)",
                    (now, grace_cutoff),
                )
            return upload_ids

    def mark_upload_finalizing(self, upload_id: str) -> bool:
        """Atomically claim a staging upload for finalization (H19).

        Must be called inside a write transaction. Sets finalizing = 1
        and returns True iff the row existed and was not already claimed.
        The transaction's BEGIN IMMEDIATE plus this flag together
        guarantee exclusive ownership of the staging row against the
        background cleanup task.
        """
        cursor = self.conn.execute(
            "UPDATE staging_uploads SET finalizing = 1 "
            "WHERE upload_id = ? AND finalizing = 0",
            (upload_id,),
        )
        return cursor.rowcount > 0

    def clear_finalizing(self, upload_id: str) -> bool:
        """Reset ``finalizing = 0`` so a stranded claim can be retried (STG-2).

        Called when a finalize attempt fails on a RECOVERABLE branch (quota
        or a transient commit error) WITHOUT deleting the staging row, so the
        background cleanup and a client retry both see an un-claimed row
        again — rather than one stuck at finalizing=1 (cap-invisible, and
        re-claim returns False so a retry would mislead with "Upload
        expired") until the grace window. Runs in its own write transaction.

        Returns:
            True if a row was updated.
        """
        with self.transaction() as conn:
            cursor = conn.execute(
                "UPDATE staging_uploads SET finalizing = 0 WHERE upload_id = ?",
                (upload_id,),
            )
            return cursor.rowcount > 0

    def get_total_staging_bytes(self, owner_id: str) -> int:
        """Return the sum of chunk_size across all open (non-expired,
        non-finalizing) staging uploads owned by the user (K3).
        """
        now = time.time()
        with self._lock:
            row = self.conn.execute(
                "SELECT COALESCE(SUM(c.chunk_size), 0) AS total "
                "FROM staging_chunks c "
                "JOIN staging_uploads u ON u.upload_id = c.upload_id "
                "WHERE u.owner_id = ? "
                "AND u.expires_at >= ? "
                "AND u.finalizing = 0",
                (owner_id, now),
            ).fetchone()
            return int(row["total"]) if row else 0

    def count_open_uploads(self, owner_id: str) -> int:
        """Count non-expired, non-finalizing staging uploads for a user
        (K3). Used to cap parallel upload sessions per user.
        """
        now = time.time()
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS cnt FROM staging_uploads "
                "WHERE owner_id = ? "
                "AND expires_at >= ? "
                "AND finalizing = 0",
                (owner_id, now),
            ).fetchone()
            return int(row["cnt"]) if row else 0

    # ──────────────────────────── Quota ────────────────────────────

    def get_user_usage(self, user_id: str) -> tuple[int, int]:
        """Get (used_bytes, quota_bytes) for a user.

        Acquires self._lock (RLock — safe to call inside a transaction).
        Earlier code relied on caller-held lock; some call sites
        (storage._quota_snapshot) forgot, producing torn reads. (#C1)
        """
        with self._lock:
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
