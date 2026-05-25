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

# Dummy Argon2id hash used to equalize timing on unknown-username
# logins. Computed lazily on first use so that importing this module is
# cheap and tests that monkey-patch Argon2 parameters do not pay the
# 128-MiB cost at import time. (#C3)
#
# The dummy plaintext is per-process random rather than the previous
# constant ``"x" * 32`` so it cannot be brute-precomputed or accidentally
# coincide with a real user's password. (#25)
_DUMMY_PASSWORD: bytes = b""
_DUMMY_PASSWORD_HASH: str | None = None

# Cap concurrent Argon2id verifications so that a burst of login
# attempts can't exhaust memory / CPU. Argon2id is intentionally
# expensive; without a bound, N concurrent requests means N × the
# configured memory footprint.
_MAX_CONCURRENT_ARGON2 = 4

# Semaphore is created lazily inside the running event loop so that an
# unrelated import (e.g. from a test runner) doesn't bind it to a
# now-stale loop. (#C4)
_argon2_semaphore: asyncio.Semaphore | None = None


def _get_argon2_semaphore() -> asyncio.Semaphore:
    """Return the process-wide semaphore, creating it on first use."""
    global _argon2_semaphore
    if _argon2_semaphore is None:
        _argon2_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_ARGON2)
    return _argon2_semaphore


def _get_dummy_hash() -> str:
    """Return a dummy Argon2 hash. Computed once per process.

    The dummy plaintext is discarded after the hash is computed so we
    don't leave 32 bytes of random-but-real plaintext in process memory
    for the lifetime of the daemon. (Round-3 M12)
    """
    global _DUMMY_PASSWORD, _DUMMY_PASSWORD_HASH
    if _DUMMY_PASSWORD_HASH is None:
        import os as _os

        # Use os.urandom for the dummy plaintext to avoid any chance of
        # collision with a real password and to prevent precomputation.
        plaintext = _os.urandom(32).hex()
        _DUMMY_PASSWORD_HASH = hash_password(plaintext)
        # Best-effort: shred the local plaintext reference. The Python
        # str is immutable; we just drop the binding here.
        _DUMMY_PASSWORD = b""
        del plaintext
    return _DUMMY_PASSWORD_HASH


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
    sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()

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
_composite_attempts: dict[tuple[str, str], deque[float]] = defaultdict(deque)
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


# Hard cap on how many (peer, username) pairs the composite limiter
# will track. An attacker who flood-logins distinct (peer, username)
# tuples is bounded to this many in-memory entries. Beyond the cap,
# new entries fall back to the DB-level rate limit only. (#H11 #87)
_COMPOSITE_MAX_KEYS: int = 8192


async def sweep_composite_attempts(window_seconds: int) -> int:
    """Periodically called to remove stale composite-limiter entries.

    Drops every key whose deque is empty after trimming entries older
    than ``window_seconds``. Also drops oldest-touched entries above the
    hard cap so a username-flood attacker cannot grow this dict without
    bound. Returns the number of keys removed (for logging).
    """
    now = time.monotonic()
    cutoff = now - window_seconds
    removed = 0
    async with _composite_lock:
        for key in list(_composite_attempts.keys()):
            dq = _composite_attempts[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del _composite_attempts[key]
                removed += 1
        if len(_composite_attempts) > _COMPOSITE_MAX_KEYS:
            # Evict the entries with the OLDEST most-recent attempt.
            # We can't use ordered dict here because defaultdict isn't
            # ordered by access; do an O(n) pick.
            excess = len(_composite_attempts) - _COMPOSITE_MAX_KEYS
            items = sorted(
                _composite_attempts.items(),
                key=lambda kv: kv[1][-1] if kv[1] else 0.0,
            )
            for key, _ in items[:excess]:
                del _composite_attempts[key]
                removed += 1
    return removed


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
_db: Database | None = None
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
    """Initialize auth module with dependencies.

    Also eagerly creates ``_argon2_semaphore`` to close the lazy-init
    race (Round-10 M7): two concurrent first-callers of
    `_get_argon2_semaphore` could otherwise each create their own
    semaphore (the `if is None: = Semaphore(...)` window is not GIL-
    protected across `await` boundaries). Creating it here, inside the
    running event loop at app startup, guarantees one instance.
    """
    global _db, _session_secret, _session_lifetime
    global _rate_limit_max, _rate_limit_window
    global _argon2_semaphore
    _db = db
    _session_secret = session_secret
    _session_lifetime = session_lifetime
    _rate_limit_max = rate_limit_max
    _rate_limit_window = rate_limit_window
    if _argon2_semaphore is None:
        _argon2_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_ARGON2)


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

    # Require explicit JSON content type. Return uniform 401 (not 415)
    # so an attacker can't probe rate-limit state by alternating
    # content-types. (Round-3 H7)
    if not request.is_json:
        await asyncio.sleep(_RATE_LIMIT_SLEEP_SECONDS)
        return _auth_failure_response()

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
            check_rate_limit,
            _db,
            username,
            peer_id,
            _rate_limit_max,
            _rate_limit_window,
        )
    except RateLimitError:
        await asyncio.sleep(_RATE_LIMIT_SLEEP_SECONDS)
        return _auth_failure_response()

    # Look up user. To prevent a timing side-channel that enumerates
    # usernames, we always run Argon2id — against the real hash if the
    # user exists, or against a fresh dummy hash otherwise. The dummy
    # hash is computed lazily inside _get_dummy_hash so import time
    # stays cheap.
    user = await asyncio.to_thread(_db.get_user_by_username, username)
    stored_hash = user["password_hash"] if user is not None else _get_dummy_hash()

    # Bound concurrent Argon2id verifications (medium). Outside this
    # semaphore, requests queue rather than piling up memory load.
    #
    # Catch ANY exception from verify_password and treat as failure.
    # In particular, argon2's InvalidHashError (which our shared.crypto
    # layer re-raises as CryptoError) would otherwise propagate to the
    # 500 handler and create a hard username-enumeration oracle: real
    # user with corrupted Argon2 hash returns 500, unknown user returns
    # 401. (Round-3 CRITICAL fix)
    async with _get_argon2_semaphore():
        try:
            password_ok = await asyncio.to_thread(
                verify_password, stored_hash, password
            )
        except Exception:
            # Log internally; from the wire it looks like any other
            # auth failure. We deliberately do not re-raise.
            import logging as _logging

            _logging.getLogger("localcloud.auth").warning(
                "verify_password raised; treating as failure",
                exc_info=True,
            )
            password_ok = False

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

        # Enforce session_version AND is_active in one DB read so an
        # operator's disable_user takes effect immediately (#H1) even if
        # the user still holds a non-expired token. Previously
        # require_auth only checked session_version, so a disabled user
        # remained usable until their token expired.
        assert _db is not None, "Auth module not initialized"
        user_status = await asyncio.to_thread(_db.get_user_status, payload["user_id"])
        if user_status is None:
            return jsonify({"error": "Authentication required"}), 401
        current_sv, is_active = user_status
        if not is_active:
            return jsonify({"error": "Authentication required"}), 401

        # Type-check sv AFTER HMAC verifies. bool is a subclass of int
        # in Python — explicitly reject so True/False can't sneak
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
