# LocalCloud - Server Configuration
#
# All server configuration in one place. Values can be overridden
# via environment variables or a config file.

from __future__ import annotations

import os
from dataclasses import dataclass


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
    def from_env(cls) -> "ServerConfig":
        """Load configuration from environment variables.

        Environment variables are prefixed with LOCALCLOUD_.
        """
        config = cls()

        config.bind_host = os.environ.get(
            "LOCALCLOUD_BIND_HOST", config.bind_host
        )
        config.bind_port = int(
            os.environ.get("LOCALCLOUD_BIND_PORT", config.bind_port)
        )
        config.data_dir = os.environ.get(
            "LOCALCLOUD_DATA_DIR", config.data_dir
        )
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
        config.session_secret = os.environ.get(
            "LOCALCLOUD_SESSION_SECRET", config.session_secret
        )
        config.session_lifetime = int(
            os.environ.get(
                "LOCALCLOUD_SESSION_LIFETIME", config.session_lifetime
            )
        )
        config.default_quota_bytes = int(
            os.environ.get(
                "LOCALCLOUD_DEFAULT_QUOTA", config.default_quota_bytes
            )
        )
        # #15: Load all configurable fields from environment
        config.rate_limit_max_attempts = int(
            os.environ.get(
                "LOCALCLOUD_RATE_LIMIT_MAX", config.rate_limit_max_attempts
            )
        )
        config.rate_limit_window_seconds = int(
            os.environ.get(
                "LOCALCLOUD_RATE_LIMIT_WINDOW", config.rate_limit_window_seconds
            )
        )
        config.staging_expiry_seconds = int(
            os.environ.get(
                "LOCALCLOUD_STAGING_EXPIRY", config.staging_expiry_seconds
            )
        )
        config.max_content_length = int(
            os.environ.get(
                "LOCALCLOUD_MAX_CONTENT_LENGTH", config.max_content_length
            )
        )

        return config

    def validate(self) -> None:
        """Validate configuration. Raises ValueError on invalid config."""
        if not self.session_secret:
            raise ValueError(
                "LOCALCLOUD_SESSION_SECRET must be set. "
                "Generate with: python -c 'import os; print(os.urandom(32).hex())'"
            )
        if len(self.session_secret) < 32:
            raise ValueError(
                "LOCALCLOUD_SESSION_SECRET must be at least 32 characters"
            )
        if self.bind_port < 1 or self.bind_port > 65535:
            raise ValueError("Invalid bind port")

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        for d in [self.data_dir, self.blob_dir, self.staging_dir]:
            os.makedirs(d, mode=0o700, exist_ok=True)
