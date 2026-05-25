# LocalCloud - Server Configuration
#
# All server configuration in one place. Values can be overridden
# via environment variables or a config file.

from __future__ import annotations

import ipaddress
import os
import stat as _stat
from dataclasses import dataclass

# Hard cap on the size of a secret-file read. A 256-bit secret encodes
# to ≤64 chars; allowing 16 KiB tolerates whitespace/comments without
# letting a misconfigured path (e.g. /dev/zero, a giant log) consume
# memory at startup.
_MAX_SECRET_FILE_BYTES: int = 16 * 1024


@dataclass
class ServerConfig:
    """Server configuration with secure defaults."""

    # ── Network ──
    # Bind exclusively to WireGuard interface
    bind_host: str = "10.0.0.1"
    bind_port: int = 8443

    # ── Storage paths ──
    data_dir: str = "/srv/cloud"
    blob_dir: str = "/srv/cloud/blobs"
    staging_dir: str = "/srv/cloud/staging"
    db_path: str = "/srv/cloud/meta.db"

    # ── Auth ──
    # Session token lifetime in seconds (default 1 hour)
    session_lifetime: int = 3600
    # HMAC secret for signing session tokens (MUST be set in production)
    session_secret: str = ""
    # Rate limiting: max login attempts per username per window
    rate_limit_max_attempts: int = 5
    rate_limit_window_seconds: int = 60

    # ── Quota ──
    # Default per-user quota in bytes (1 GiB)
    default_quota_bytes: int = 1 * 1024 * 1024 * 1024
    # Staging upload expiry in seconds (default 1 hour)
    staging_expiry_seconds: int = 3600

    # ── Security ──
    # Maximum request body size (slightly larger than chunk size + overhead)
    max_content_length: int = 5 * 1024 * 1024  # 5 MiB

    @classmethod
    def from_env(cls) -> ServerConfig:
        """Load configuration from environment variables.

        Environment variables are prefixed with LOCALCLOUD_.
        """
        config = cls()

        config.bind_host = os.environ.get("LOCALCLOUD_BIND_HOST", config.bind_host)
        config.bind_port = int(os.environ.get("LOCALCLOUD_BIND_PORT", config.bind_port))
        config.data_dir = os.environ.get("LOCALCLOUD_DATA_DIR", config.data_dir)
        config.blob_dir = os.environ.get(
            "LOCALCLOUD_BLOB_DIR",
            os.path.join(config.data_dir, "blobs"),
        )
        config.staging_dir = os.environ.get(
            "LOCALCLOUD_STAGING_DIR",
            os.path.join(config.data_dir, "staging"),
        )
        config.db_path = os.environ.get(
            "LOCALCLOUD_DB_PATH",
            os.path.join(config.data_dir, "meta.db"),
        )
        # Session secret: prefer a root-owned file over an environment
        # variable, since env vars are exposed to subprocesses via
        # /proc/<pid>/environ. The file path can also come from
        # systemd's LoadCredential=.
        secret_file = os.environ.get("LOCALCLOUD_SESSION_SECRET_FILE")
        if secret_file:
            config.session_secret = _read_secret_file(secret_file)
        else:
            config.session_secret = os.environ.get(
                "LOCALCLOUD_SESSION_SECRET", config.session_secret
            )
        config.session_lifetime = int(
            os.environ.get("LOCALCLOUD_SESSION_LIFETIME", config.session_lifetime)
        )
        config.default_quota_bytes = int(
            os.environ.get("LOCALCLOUD_DEFAULT_QUOTA", config.default_quota_bytes)
        )
        # #15: Load all configurable fields from environment
        config.rate_limit_max_attempts = int(
            os.environ.get("LOCALCLOUD_RATE_LIMIT_MAX", config.rate_limit_max_attempts)
        )
        config.rate_limit_window_seconds = int(
            os.environ.get(
                "LOCALCLOUD_RATE_LIMIT_WINDOW", config.rate_limit_window_seconds
            )
        )
        config.staging_expiry_seconds = int(
            os.environ.get("LOCALCLOUD_STAGING_EXPIRY", config.staging_expiry_seconds)
        )
        config.max_content_length = int(
            os.environ.get("LOCALCLOUD_MAX_CONTENT_LENGTH", config.max_content_length)
        )

        return config

    def validate(self) -> None:
        """Validate configuration. Raises ValueError on invalid config."""
        if not self.session_secret:
            raise ValueError(
                "LOCALCLOUD_SESSION_SECRET must be set. "
                "Generate with: python -c 'import os; print(os.urandom(32).hex())'"
            )
        # Require at least 64 characters of *encoded* secret. 64 hex
        # chars and 44 base64 chars both encode 256 bits of entropy;
        # since we can't reliably tell the encoding here, demand 64
        # characters across the board. This guarantees ≥256 bits of
        # entropy even in the worst-case (base64 → 6 bits/char → 384
        # bits, hex → 4 bits/char → 256 bits).
        if len(self.session_secret) < 64:
            raise ValueError(
                "LOCALCLOUD_SESSION_SECRET must be at least 64 characters "
                "(256 bits of entropy)"
            )
        if self.bind_port < 1 or self.bind_port > 65535:
            raise ValueError("Invalid bind port")

        # Refuse public-network bind addresses. The deployment is
        # WireGuard-only; binding to 0.0.0.0/::/loopback-only-aliases is
        # a misconfiguration. Operator can override by setting
        # ``LOCALCLOUD_ALLOW_PUBLIC_BIND=1`` if they really mean it.
        # (#F12.4)
        if os.environ.get("LOCALCLOUD_ALLOW_PUBLIC_BIND") != "1":
            try:
                ip = ipaddress.ip_address(self.bind_host)
            except ValueError as exc:
                raise ValueError(f"Invalid bind_host: {self.bind_host!r}") from exc
            if ip.is_unspecified:
                raise ValueError(
                    f"bind_host {self.bind_host!r} would accept "
                    "non-WireGuard connections; set "
                    "LOCALCLOUD_ALLOW_PUBLIC_BIND=1 to override."
                )
            if not (ip.is_private or ip.is_loopback or ip.is_link_local):
                raise ValueError(
                    f"bind_host {self.bind_host!r} is a public address; "
                    "set LOCALCLOUD_ALLOW_PUBLIC_BIND=1 to override."
                )

        # Paths must be absolute so they don't depend on the daemon's
        # CWD (#61).
        for label, path in (
            ("data_dir", self.data_dir),
            ("blob_dir", self.blob_dir),
            ("staging_dir", self.staging_dir),
            ("db_path", self.db_path),
        ):
            if not os.path.isabs(path):
                raise ValueError(f"{label} must be an absolute path: {path!r}")

        if self.default_quota_bytes < 0:
            raise ValueError("default_quota_bytes must be >= 0")
        if self.staging_expiry_seconds < 1:
            raise ValueError("staging_expiry_seconds must be positive")
        if self.session_lifetime < 60:
            raise ValueError("session_lifetime must be >= 60 seconds")
        if self.session_lifetime > 86_400:
            # 24h hard cap — long-lived tokens widen the
            # session_version-bump revocation window. (Round-4 M8)
            raise ValueError("session_lifetime must be <= 86400 seconds (24h)")
        if self.rate_limit_max_attempts < 1:
            raise ValueError("rate_limit_max_attempts must be >= 1")
        if self.rate_limit_window_seconds < 1:
            raise ValueError("rate_limit_window_seconds must be >= 1")
        if self.max_content_length < 1024:
            raise ValueError("max_content_length too small")

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        for d in [self.data_dir, self.blob_dir, self.staging_dir]:
            os.makedirs(d, mode=0o700, exist_ok=True)


def _read_secret_file(path: str) -> str:
    """Read a secret from a file, refusing world/group-readable permissions.

    The file should be 0400/0600 and owned by the service user. We
    reject anything group- or world-readable so that a lax umask
    doesn't silently expose the HMAC signing key. We also refuse to
    follow symlinks (O_NOFOLLOW) — an attacker who can plant a symlink
    in a writable directory shouldn't be able to redirect us to an
    arbitrary file. fstat is performed on the already-opened fd to
    avoid a TOCTOU window between stat and open.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        raise ValueError(f"Could not open session secret file {path}") from e
    try:
        st = os.fstat(fd)
        # Reject non-regular files (FIFO, socket, device). A FIFO would
        # block forever on read; /dev/zero would return endless bytes.
        if not _stat.S_ISREG(st.st_mode):
            raise ValueError(f"Session secret file {path} is not a regular file")
        if st.st_mode & 0o077:
            raise ValueError(
                f"Session secret file {path} is group/world-readable "
                f"(mode={oct(st.st_mode & 0o777)}); require 0400 or 0600"
            )
        # Ownership check: must be root or the current effective user.
        # Anything else means an unrelated user wrote this file, which
        # would let them rotate the HMAC key out from under us.
        if st.st_uid not in (0, os.geteuid()):
            raise ValueError(
                f"Session secret file {path} owned by uid {st.st_uid}; "
                f"require root or current user ({os.geteuid()})"
            )
        with os.fdopen(fd, "rb") as f:
            fd = -1
            # Bounded read so a misconfigured path can't trigger OOM.
            data = f.read(_MAX_SECRET_FILE_BYTES + 1)
            if len(data) > _MAX_SECRET_FILE_BYTES:
                raise ValueError(
                    f"Session secret file {path} exceeds "
                    f"{_MAX_SECRET_FILE_BYTES}-byte cap"
                )
            return data.decode("utf-8").strip()
    finally:
        if fd >= 0:
            os.close(fd)
