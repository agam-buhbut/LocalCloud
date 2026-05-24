# LocalCloud - Server Authentication
#
# Application-layer authentication: Argon2id password verification,
# HMAC-signed session tokens with peer binding, and per-(peer,user)
# composite-key rate limiting. All error responses are deliberately
# generic to prevent info leakage.

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
import unicodedata
import uuid
from collections import defaultdict, deque
from functools import wraps
from typing import Deque, Dict, Optional, Tuple

from quart import Blueprint, jsonify, request

from server.database import Database
from shared.crypto import hash_password, verify_password
from shared.exceptions import AuthError, RateLimitError, SessionExpiredError

# ──────────────────────────── Session Token ────────────────────────────

# Maximum token length to prevent resource exhaustion
_MAX_TOKEN_LEN = 4096

# Maximum permissible JSON body for /login. Larger requests are rejected
# at the route handler before reaching get_json so an attacker can't
# tie up Argon2 budget by submitting megabyte-sized "passwords".
_LOGIN_MAX_CONTENT_LENGTH = 4096

# Constant sleep budget when rate-limited. Keeps the response timing
# of a rate-limit reject indistinguishable from an auth-failure path
# that ran Argon2id + DB lookup. ~150ms is in the same ballpark as an
# Argon2id verify on commodity hardware.
_RATE_LIMIT_SLEEP_SECONDS = 0.150

# Dummy Argon2id hash computed once at startup so that the login
# handler can verify against it when a username is unknown, equalizing
# timing with the valid-username branch and preventing enumeration.
_DUMMY_PASSWORD_HASH = hash_password("x" * 32)

# Cap concurrent Argon2id verifications so that a burst of login
# attempts can't exhaust memory / CPU. Argon2id is intentionally
# expensive; without a bound, N concurrent requests means N × the
# configured memory footprint. Hardcoded conservative value — adjust
# via redeployment if profiling shows headroom.
_MAX_CONCURRENT_ARGON2 = 4
_argon2_semaphore: asyncio.Semaphore = asyncio.Semaphore(_MAX_CONCURRENT_ARGON2)

# Username canonicalization regex (post-NFKC + casefold + strip).
# Anchored: full-string match. Charset is intentionally narrow.
_USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,64}$")


def _canonicalize_username(raw: str) -> str:
    """Normalize and validate a username.

    Applies NFKC normalization, casefold, and surrounding-whitespace
    strip, then enforces a narrow charset. This prevents confusable
    Unicode (e.g. fullwidth "ＡＤＭＩＮ") from impersonating an existing
    account and rejects control characters like NUL.

    Raises:
        AuthError: with a generic message on any rejection.
    """
    if not isinstance(raw, str):
        raise AuthError("Authentication failed")
    # NUL byte rejection BEFORE normalization — NFKC could otherwise
    # collapse certain compositions and obscure the embedded NUL.
    if "\x00" in raw:
        raise AuthError("Authentication failed")
    normalized = unicodedata.normalize("NFKC", raw).casefold().strip()
    if "\x00" in normalized:
        raise AuthError("Authentication failed")
    if not _USERNAME_RE.match(normalized):
        raise AuthError("Authentication failed")
    return normalized


def create_session_token(
    user_id: str,
    username: str,
    secret: str,
    lifetime: int = 3600,
    peer_pubkey: str = "",
    session_version: int = 1,
) -> str:
    """Create an HMAC-SHA256 signed session token.

    Token payload: {user_id, username, exp, iat, jti, peer, sv}
    Format: base64url(payload).hex(signature)

    The `sv` (session_version) field lets the server revoke all
    outstanding tokens for a user by bumping the stored counter.

    Args:
        user_id: User identifier.
        username: Username (canonical form).
        secret: HMAC signing secret.
        lifetime: Token lifetime in seconds.
        peer_pubkey: WireGuard peer identity for binding (#5). MUST
            be non-empty — empty peer would silently bypass the
            peer-binding check on subsequent requests.
        session_version: Snapshotted from users.session_version at
            issue time; an operator bump revokes this token.

    Raises:
        ValueError: if peer_pubkey is empty/falsy. Refusing to mint is
            preferable to issuing an unbound token.
    """
    if not peer_pubkey:
        raise ValueError("peer_pubkey is required for session tokens")
    now = time.time()
    payload = {
        "user_id": user_id,
        "username": username,
        "iat": now,
        "exp": now + lifetime,
        "jti": uuid.uuid4().hex,
        "peer": peer_pubkey,
        "sv": session_version,
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

    Uses constant-time HMAC comparison. Peer binding is MANDATORY:
    both the token's `peer` claim and the caller-supplied
    `expected_peer` must be non-empty and equal.

    Raises SessionExpiredError on invalid, expired, or peer-mismatched
    tokens.
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
        for field_name in ("user_id", "username", "exp", "iat"):
            if field_name not in payload:
                raise SessionExpiredError()

        # Type-check expiration AFTER HMAC verifies — a forged payload
        # can't reach here, but a malformed valid-signed token from a
        # future code path shouldn't crash. (#H13)
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)) or isinstance(exp, bool):
            raise SessionExpiredError()
        if time.time() > exp:
            raise SessionExpiredError()

        # Peer binding — MANDATORY (#H9). A missing/empty token peer or
        # missing/empty expected_peer is a hard failure. We never accept
        # a token that lacks an issued binding, and we never accept a
        # request that fails to present a peer identity.
        token_peer = payload.get("peer")
        if not isinstance(token_peer, str) or not token_peer:
            raise SessionExpiredError()
        if not expected_peer or token_peer != expected_peer:
            raise SessionExpiredError()

        return payload

    except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise SessionExpiredError() from e


# ──────────────────────────── Rate Limiting ────────────────────────────

# Global IP rate limit (higher than per-user to allow shared IPs)
_IP_RATE_LIMIT_MULTIPLIER = 5

# In-memory composite-key rate limiter (#H11).
# Key: (peer_ip, canonical_username) — prevents one peer from locking
# out other peers via failed logins against their usernames. DB-backed
# per-username and per-IP counters remain as defense-in-depth but the
# composite key is authoritative for the auth decision.
#
# Trade-off: in-memory state does not survive restart and is per-process.
# For a single-process WireGuard-fronted deployment this is acceptable;
# DB-level composite tracking would require a schema change in
# server/database.py which is out of scope for this fix.
_composite_attempts: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
_composite_lock = asyncio.Lock()


async def _composite_rate_limit_check(
    peer_ip: str,
    username: str,
    max_attempts: int,
    window_seconds: int,
) -> bool:
    """Return True if (peer_ip, username) is over the limit.

    Trims expired entries on each call. Caller is responsible for
    recording a failed attempt via `_composite_rate_limit_record`.
    """
    now = time.monotonic()
    cutoff = now - window_seconds
    key = (peer_ip, username)
    async with _composite_lock:
        dq = _composite_attempts[key]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if not dq:
            # Don't leave empty deques lying around forever.
            del _composite_attempts[key]
            return False
        return len(dq) >= max_attempts


async def _composite_rate_limit_record(peer_ip: str, username: str) -> None:
    """Record a failed login attempt under the composite key."""
    now = time.monotonic()
    key = (peer_ip, username)
    async with _composite_lock:
        _composite_attempts[key].append(now)


async def _composite_rate_limit_clear(peer_ip: str, username: str) -> None:
    """Clear composite-key attempts on successful login."""
    key = (peer_ip, username)
    async with _composite_lock:
        _composite_attempts.pop(key, None)


def check_rate_limit(
    db: Database,
    username: str,
    ip_address: str,
    max_attempts: int,
    window_seconds: int,
) -> None:
    """Check whether a username or IP has exceeded the DB-backed limit.

    #6: Checks both per-username AND per-IP limits. IP limit is higher
    to accommodate multiple users behind NAT/shared IPs.

    Cleanup is handled by a periodic background task (#11). This
    function is the legacy DB-level pre-filter; the authoritative
    auth-decision rate limit is the composite (peer, username)
    in-memory check (#H11).

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


def _auth_failure_response():
    """Generic 401 response. Used uniformly for every failure path
    (bad creds, rate-limited, malformed body, oversized body) to avoid
    leaking which gate the request tripped. (#H12)
    """
    return jsonify({"error": "Authentication failed"}), 401


@auth_bp.route("/login", methods=["POST"])
async def login():
    """Authenticate user and return a session token.

    Request body: {"username": str, "password": str}
    Response: {"token": str} on success
              {"error": "Authentication failed"} (401) on ANY failure
              path — including rate-limit, malformed body, missing
              peer identity. The status code is uniformly 401 so an
              attacker cannot probe rate-limit state. (#H12)
    """
    assert _db is not None, "Auth module not initialized"

    # Cap pre-parse body size so an oversized "password" can't consume
    # Argon2 budget. (medium)
    if (
        request.content_length is not None
        and request.content_length > _LOGIN_MAX_CONTENT_LENGTH
    ):
        await asyncio.sleep(_RATE_LIMIT_SLEEP_SECONDS)
        return _auth_failure_response()

    # Require explicit JSON content type. (medium)
    if not request.is_json:
        await asyncio.sleep(_RATE_LIMIT_SLEEP_SECONDS)
        return jsonify({"error": "Unsupported Media Type"}), 415

    # Validate peer identity BEFORE doing any expensive work. If we
    # can't bind a session, we won't mint one. (#H9)
    peer_id = _get_peer_identity()
    if not peer_id:
        await asyncio.sleep(_RATE_LIMIT_SLEEP_SECONDS)
        return _auth_failure_response()

    data = await request.get_json(silent=True)
    if not data or "username" not in data or "password" not in data:
        await asyncio.sleep(_RATE_LIMIT_SLEEP_SECONDS)
        return _auth_failure_response()

    # Canonicalize username BEFORE the DB lookup. Invalid usernames
    # are indistinguishable from wrong-password failures from the
    # client's perspective. (#H10)
    try:
        username = _canonicalize_username(str(data["username"]))
    except AuthError:
        await asyncio.sleep(_RATE_LIMIT_SLEEP_SECONDS)
        return _auth_failure_response()

    password = str(data["password"])
    if len(password) > 1024:
        await asyncio.sleep(_RATE_LIMIT_SLEEP_SECONDS)
        return _auth_failure_response()

    # Composite-key rate limit (#H11). Authoritative — runs BEFORE the
    # DB-level legacy check so we don't leak whether the per-username
    # global counter is hot.
    if await _composite_rate_limit_check(
        peer_id, username, _rate_limit_max, _rate_limit_window
    ):
        await asyncio.sleep(_RATE_LIMIT_SLEEP_SECONDS)
        return _auth_failure_response()

    # Legacy DB-level rate limit (#6): kept as defense-in-depth for
    # cross-process / cross-restart awareness. A trip here returns the
    # same generic 401, not 429 (#H12).
    try:
        await asyncio.to_thread(
            check_rate_limit, _db, username, peer_id,
            _rate_limit_max, _rate_limit_window
        )
    except RateLimitError:
        await asyncio.sleep(_RATE_LIMIT_SLEEP_SECONDS)
        return _auth_failure_response()

    # Look up user. To prevent a timing side-channel that enumerates
    # usernames, we always run Argon2id — against the real hash if the
    # user exists, or against a fixed dummy hash otherwise.
    user = await asyncio.to_thread(_db.get_user_by_username, username)
    stored_hash = user["password_hash"] if user is not None else _DUMMY_PASSWORD_HASH

    # Bound concurrent Argon2id verifications (medium). Outside this
    # semaphore, requests queue rather than piling up memory load.
    async with _argon2_semaphore:
        password_ok = await asyncio.to_thread(
            verify_password, stored_hash, password
        )

    if user is None or not user["is_active"] or not password_ok:
        await _composite_rate_limit_record(peer_id, username)
        await asyncio.to_thread(_db.record_login_attempt, username, peer_id)
        return _auth_failure_response()

    # #6: Successful login — clear previous failed attempts at both layers
    await _composite_rate_limit_clear(peer_id, username)
    await asyncio.to_thread(_db.clear_login_attempts, username)

    # Create session token bound to WireGuard peer (#5) and snapshot the
    # user's current session_version so an operator bump revokes this
    # token. create_session_token raises ValueError on empty peer; we
    # validated peer_id above so this is belt-and-braces.
    try:
        token = create_session_token(
            user["user_id"],
            username,
            _session_secret,
            _session_lifetime,
            peer_pubkey=peer_id,
            session_version=int(user.get("session_version", 1)),
        )
    except ValueError:
        # Should never trigger given the peer_id guard above. Fail
        # generically rather than reveal the internal contract.
        return _auth_failure_response()

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

        peer_id = _get_peer_identity()
        if not peer_id:
            # Without a peer identity we cannot enforce binding. (#H9)
            return jsonify({"error": "Authentication required"}), 401

        try:
            payload = verify_session_token(
                token, _session_secret, expected_peer=peer_id
            )
        except SessionExpiredError:
            return jsonify({"error": "Authentication required"}), 401

        # Enforce session_version — tokens issued before an operator
        # bump are rejected even if still within their lifetime.
        assert _db is not None, "Auth module not initialized"
        current_sv = await asyncio.to_thread(
            _db.get_session_version, payload["user_id"]
        )
        if current_sv is None:
            return jsonify({"error": "Authentication required"}), 401

        # Type-check sv AFTER HMAC verifies (#H13). bool is a subclass of
        # int in Python — explicitly reject so True/False can't sneak
        # through a comparison.
        token_sv = payload.get("sv")
        if not isinstance(token_sv, int) or isinstance(token_sv, bool):
            return jsonify({"error": "Authentication required"}), 401
        if token_sv != current_sv:
            return jsonify({"error": "Authentication required"}), 401

        # Attach user info to request context
        request.user_id = payload["user_id"]  # type: ignore
        request.username = payload["username"]  # type: ignore

        return await f(*args, **kwargs)

    return decorated
