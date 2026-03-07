# LocalCloud - Server Authentication
#
# Application-layer authentication: Argon2id password verification,
# HMAC-signed session tokens with peer binding, and per-username rate limiting.
# All error responses are deliberately generic to prevent info leakage.

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from functools import wraps
from typing import Optional

from quart import Blueprint, jsonify, request

from server.database import Database
from shared.crypto import hash_password, verify_password
from shared.exceptions import AuthError, RateLimitError, SessionExpiredError

# ──────────────────────────── Session Token ────────────────────────────

# Maximum token length to prevent resource exhaustion
_MAX_TOKEN_LEN = 4096


def create_session_token(
    user_id: str,
    username: str,
    secret: str,
    lifetime: int = 3600,
    peer_pubkey: str = "",
) -> str:
    """Create an HMAC-SHA256 signed session token.

    Token payload: {user_id, username, exp, iat, jti, peer}
    Format: base64url(payload).hex(signature)

    Args:
        user_id: User identifier
        username: Username
        secret: HMAC signing secret
        lifetime: Token lifetime in seconds
        peer_pubkey: WireGuard peer public key fingerprint for binding (#5)
    """
    now = time.time()
    payload = {
        "user_id": user_id,
        "username": username,
        "iat": now,
        "exp": now + lifetime,
        "jti": uuid.uuid4().hex,  # Token ID for revocation (#5)
        "peer": peer_pubkey,      # WireGuard peer binding (#5)
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    # HMAC-SHA256 signature
    sig = hmac.new(
        secret.encode(), payload_bytes, hashlib.sha256
    ).hexdigest()

    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode().rstrip("=")
    return f"{payload_b64}.{sig}"


def verify_session_token(
    token: str,
    secret: str,
    expected_peer: str = "",
) -> dict:
    """Verify and decode a session token.

    Uses constant-time HMAC comparison. Validates peer binding if
    expected_peer is provided (#5).

    Raises SessionExpiredError on invalid, expired, or peer-mismatched tokens.
    """
    if not token or len(token) > _MAX_TOKEN_LEN:
        raise SessionExpiredError()

    try:
        parts = token.split(".", 1)
        if len(parts) != 2:
            raise SessionExpiredError()

        payload_b64, sig = parts

        # Normalize base64 padding (#14)
        padding_needed = 4 - (len(payload_b64) % 4)
        if padding_needed != 4:
            payload_b64 += "=" * padding_needed

        payload_bytes = base64.urlsafe_b64decode(payload_b64)

        # Constant-time signature verification
        expected_sig = hmac.new(
            secret.encode(), payload_bytes, hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(sig, expected_sig):
            raise SessionExpiredError()

        payload = json.loads(payload_bytes)

        # Validate required fields
        if not isinstance(payload, dict):
            raise SessionExpiredError()
        for field in ("user_id", "username", "exp", "iat"):
            if field not in payload:
                raise SessionExpiredError()

        # Check expiration
        if time.time() > payload.get("exp", 0):
            raise SessionExpiredError()

        # Verify peer binding (#5) — if expected_peer is set,
        # token must match
        if expected_peer and payload.get("peer", "") != expected_peer:
            raise SessionExpiredError()

        return payload

    except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
        raise SessionExpiredError()


# ──────────────────────────── Rate Limiting ────────────────────────────

# Global IP rate limit (higher than per-user to allow shared IPs)
_IP_RATE_LIMIT_MULTIPLIER = 5


def check_rate_limit(
    db: Database,
    username: str,
    ip_address: str,
    max_attempts: int,
    window_seconds: int,
) -> None:
    """Check if a username or IP has exceeded the login rate limit.

    #6: Checks both per-username AND per-IP limits. IP limit is higher
    to accommodate multiple users behind NAT/shared IPs.

    Cleanup is handled by periodic background task (#11), not here.

    Raises RateLimitError if too many recent attempts.
    """
    # Per-username check
    count = db.count_recent_attempts(username, window_seconds)
    if count >= max_attempts:
        raise RateLimitError()

    # Per-IP check (higher threshold) #6
    if ip_address:
        ip_count = db.count_recent_attempts_by_ip(ip_address, window_seconds)
        if ip_count >= max_attempts * _IP_RATE_LIMIT_MULTIPLIER:
            raise RateLimitError()


# ──────────────────────────── Auth Blueprint ────────────────────────────

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# These will be set by the app factory
_db: Optional[Database] = None
_session_secret: str = ""
_session_lifetime: int = 3600
_rate_limit_max: int = 5
_rate_limit_window: int = 60


def init_auth(
    db: Database,
    session_secret: str,
    session_lifetime: int = 3600,
    rate_limit_max: int = 5,
    rate_limit_window: int = 60,
) -> None:
    """Initialize auth module with dependencies."""
    global _db, _session_secret, _session_lifetime
    global _rate_limit_max, _rate_limit_window
    _db = db
    _session_secret = session_secret
    _session_lifetime = session_lifetime
    _rate_limit_max = rate_limit_max
    _rate_limit_window = rate_limit_window


def _get_peer_identity() -> str:
    """Extract WireGuard peer identity from the request.

    In a WireGuard-only deployment, the source IP within the tunnel
    uniquely identifies the peer. This is used for session binding (#5).
    """
    # WireGuard source IP serves as peer identity
    return request.remote_addr or ""


@auth_bp.route("/login", methods=["POST"])
async def login():
    """Authenticate user and return a session token.

    Request body: {"username": str, "password": str}
    Response: {"token": str} on success
              {"error": "Authentication failed"} on failure

    Error response is deliberately identical for wrong username and
    wrong password to prevent username enumeration.

    #6: Rate limit check includes IP dimension. Attempts are only
    recorded AFTER failed authentication. Successful logins clear attempts.
    """
    assert _db is not None, "Auth module not initialized"

    data = await request.get_json(silent=True)
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Authentication failed"}), 401

    username = str(data["username"])
    password = str(data["password"])

    # Validate input lengths
    if len(username) > 255 or len(password) > 1024:
        return jsonify({"error": "Authentication failed"}), 401

    # Get IP for rate limiting (#6)
    ip_address = _get_peer_identity()

    # Rate limit check (#6: includes IP dimension, cleanup moved to background #11)
    try:
        await asyncio.to_thread(
            check_rate_limit, _db, username, ip_address,
            _rate_limit_max, _rate_limit_window
        )
    except RateLimitError:
        return jsonify({"error": "Authentication failed"}), 429

    # Look up user
    user = await asyncio.to_thread(_db.get_user_by_username, username)
    if user is None or not user["is_active"]:
        # #6: Record failed attempt AFTER check (not before)
        await asyncio.to_thread(_db.record_login_attempt, username, ip_address)
        # Deliberate: same error as wrong password
        return jsonify({"error": "Authentication failed"}), 401

    # Verify password (constant-time via argon2-cffi)
    if not await asyncio.to_thread(verify_password, user["password_hash"], password):
        # #6: Record failed attempt only on actual failures
        await asyncio.to_thread(_db.record_login_attempt, username, ip_address)
        return jsonify({"error": "Authentication failed"}), 401

    # #6: Successful login — clear previous failed attempts
    await asyncio.to_thread(_db.clear_login_attempts, username)

    # Create session token bound to WireGuard peer (#5)
    peer_id = _get_peer_identity()
    token = create_session_token(
        user["user_id"],
        username,
        _session_secret,
        _session_lifetime,
        peer_pubkey=peer_id,
    )

    return jsonify({"token": token}), 200


# ──────────────────────────── Auth Middleware ────────────────────────────


def require_auth(f):
    """Decorator that verifies the session token on every request.

    Verifies HMAC signature, expiration, and WireGuard peer binding (#5).
    Sets request.user_id and request.username on success.
    """

    @wraps(f)
    async def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header[7:]

        try:
            peer_id = _get_peer_identity()
            payload = verify_session_token(
                token, _session_secret, expected_peer=peer_id
            )
        except SessionExpiredError:
            return jsonify({"error": "Authentication required"}), 401

        # Attach user info to request context
        request.user_id = payload["user_id"]  # type: ignore
        request.username = payload["username"]  # type: ignore

        return await f(*args, **kwargs)

    return decorated
