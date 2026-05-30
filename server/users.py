# LocalCloud - User directory (X25519 enrollment + pubkey lookup)
#
# Item 2C. The server stores each user's long-term X25519 key-agreement
# public key alongside their Ed25519 identity key, plus an Ed25519
# self-signature over the (domain-separated, username-bound) X25519 key.
# A sharer/publisher who has pinned a recipient's Ed25519 fingerprint
# out-of-band can then verify the X25519 key transitively, so the hostile
# server cannot substitute its own key (T-2C).
#
# Security posture:
#   * The server VERIFIES the enroll self-signature (defense in depth),
#     but the authenticity guarantee rests on the *client* re-verifying
#     before wrapping — the server is hostile.
#   * The directory lookup is a uniform, fixed-SIZE, constant-DEADLINE
#     response so neither body length nor latency distinguishes an
#     unknown user from a keyless or enrolled one (T-N2 enumeration).
#   * All routes require auth; all error bodies are generic.

from __future__ import annotations

import asyncio
import time

import keycore
from quart import Blueprint, jsonify, request

from server.auth import require_auth
from server.state import app_state, current_identity
from shared.exceptions import AuthError
from shared.usernames import (
    X25519_PUBKEY_LEN,
    build_enroll_signing_input,
    canonicalize_username,
)

users_bp = Blueprint("users", __name__, url_prefix="/api/users")

# Exact wire lengths for the enrolled key material.
_X25519_LEN = X25519_PUBKEY_LEN  # 32
_ED25519_LEN = 32
_SELF_SIG_LEN = 64  # Ed25519 signature

# Hex widths used to pad the directory response to a constant byte length
# regardless of whether a field is present. Absent fields are returned as
# all-zero hex of the same width so the JSON body is byte-for-byte the
# same size for unknown / keyless / enrolled users (no length oracle).
_X25519_HEX_WIDTH = _X25519_LEN * 2  # 64
_ED25519_HEX_WIDTH = _ED25519_LEN * 2  # 64
_SELF_SIG_HEX_WIDTH = _SELF_SIG_LEN * 2  # 128

# Constant-deadline budget for the directory lookup, mirroring the
# share-endpoint timing envelope (server/storage.py _SHARE_TIMING_BUDGET_S
# = 0.150). A row that exists touches BLOB columns while an absent one is
# an empty index probe; capping the wall-clock at a fixed deadline closes
# that timing delta so existence is not measurable (T-N2 / L6).
_DIRECTORY_TIMING_BUDGET_S = 0.150

# Pagination caps for /enrolled, mirroring list_files (storage.py).
_DEFAULT_ENROLLED_LIMIT = 50
_MAX_ENROLLED_LIMIT = 200

# Reject absurd usernames before canonicalization, matching the share
# endpoint's pre-canonicalize length guard.
_MAX_USERNAME_LEN = 64


@users_bp.route("/enroll_x25519", methods=["POST"])
@require_auth
async def enroll_x25519():
    """Enroll the caller's own X25519 public key + Ed25519 self-signature.

    Acts on the caller's own row only (the identity comes from the verified
    session, never the body). The server re-verifies the self-signature
    against the caller's already-registered Ed25519 key as defense in
    depth, then persists the X25519 key.

    Request body: ``{"x25519_pubkey": <hex 32>, "self_sig": <hex 64>}``.

    Responses:
        200 ``{"status": "enrolled"}`` on success.
        400 ``{"error": "Invalid request"}`` on bad hex/length, a
            self-signature that fails verification, OR a caller with no
            Ed25519 key on file. The keyless case is folded into the
            generic 400 (NOT a distinct 409) so the response does not
            disclose server-side identity state the client already knows
            locally (uniform-response discipline).
    """
    state = app_state()
    identity = current_identity()

    data = await request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request"}), 400
    raw_x = data.get("x25519_pubkey")
    raw_sig = data.get("self_sig")
    if not isinstance(raw_x, str) or not isinstance(raw_sig, str):
        return jsonify({"error": "Invalid request"}), 400

    try:
        x25519_pub = bytes.fromhex(raw_x)
        self_sig = bytes.fromhex(raw_sig)
    except ValueError:
        return jsonify({"error": "Invalid request"}), 400
    if len(x25519_pub) != _X25519_LEN or len(self_sig) != _SELF_SIG_LEN:
        return jsonify({"error": "Invalid request"}), 400

    # Canonicalize the caller's own username for the signed input. The
    # token's username claim is already canonical (login canonicalizes
    # before minting), but re-canonicalizing is cheap and guarantees the
    # exact bytes the client signed over.
    try:
        canonical_username = canonicalize_username(identity.username)
    except AuthError:
        return jsonify({"error": "Invalid request"}), 400

    user = await asyncio.to_thread(state.db.get_user_by_id, identity.user_id)
    if user is None:
        return jsonify({"error": "Invalid request"}), 400
    ed25519_pub = bytes(user.get("ed25519_pubkey") or b"")
    if len(ed25519_pub) != _ED25519_LEN:
        # No (usable) Ed25519 identity on file: the chain root is not
        # established yet. Generic 400 per the uniform-response rule.
        return jsonify({"error": "Invalid request"}), 400

    signing_input = build_enroll_signing_input(canonical_username, x25519_pub)
    try:
        # keycore native extension: no .pyi stub, verify_signature exists
        # at runtime (same call shape as client/encryptor.py).
        ok = keycore.verify_signature(  # type: ignore[reportAttributeAccessIssue]
            ed25519_pub, signing_input, self_sig
        )
    except Exception:
        # A malformed key/signature surfaces as a verify failure, not a
        # 500 — keep the response generic and fail closed.
        ok = False
    if not ok:
        return jsonify({"error": "Invalid request"}), 400

    def _store() -> bool:
        # set_user_x25519 opens its own write transaction; returns True iff
        # the UPDATE matched a row.
        return state.db.set_user_x25519(canonical_username, x25519_pub, self_sig)

    updated = await asyncio.to_thread(_store)
    if not updated:
        # The UPDATE matched 0 rows (e.g. the canonical username has no row,
        # a race with account deletion). Do NOT falsely report "enrolled";
        # fold into the generic 400 to keep the response uniform and close
        # the latent fail-open.
        return jsonify({"error": "Invalid request"}), 400
    return jsonify({"status": "enrolled"}), 200


@users_bp.route("/<username>/pubkeys", methods=["GET"])
@require_auth
async def get_pubkeys(username: str):
    """Return a user's Ed25519 + X25519 + self-signature (directory lookup).

    ALWAYS returns 200 with a fixed-shape, fixed-LENGTH body so existence
    is not observable. Present fields are lowercase hex; absent fields are
    all-zero hex of the SAME width (so the JSON byte length is identical
    for unknown / keyless / enrolled users). A constant-deadline envelope
    caps wall-clock latency so timing does not leak existence either.

    The client MUST treat an all-zero ``x25519``/``self_sig`` as "not
    enrolled" and fail closed (it cannot verify an absent self-signature),
    so returning zeros for the absent case is safe.
    """
    state = app_state()
    # Bind the caller identity so the route requires a valid session even
    # though the response is uniform (kept symmetric with other routes).
    current_identity()

    # Start the deadline BEFORE the length check / canonicalization /
    # lookup so all of that latency is inside the constant envelope.
    started = time.monotonic()

    ed_hex = "0" * _ED25519_HEX_WIDTH
    x_hex = "0" * _X25519_HEX_WIDTH
    sig_hex = "0" * _SELF_SIG_HEX_WIDTH

    # Over-long or non-canonicalizable usernames resolve to the same
    # all-empty (all-zero hex) response — never a distinct error.
    canonical: str | None = None
    if isinstance(username, str) and 0 < len(username) <= _MAX_USERNAME_LEN:
        try:
            canonical = canonicalize_username(username)
        except AuthError:
            canonical = None

    if canonical is not None:
        row = await asyncio.to_thread(state.db.get_user_by_username, canonical)
        if row is not None:
            ed = bytes(row.get("ed25519_pubkey") or b"")
            x = bytes(row.get("x25519_pubkey") or b"")
            sig = bytes(row.get("x25519_self_sig") or b"")
            if len(ed) == _ED25519_LEN:
                ed_hex = ed.hex()
            # Only surface X25519 + self-sig together: a half-enrolled row
            # is not usable and must not be advertised as enrolled.
            if len(x) == _X25519_LEN and len(sig) == _SELF_SIG_LEN:
                x_hex = x.hex()
                sig_hex = sig.hex()

    body = {"ed25519": ed_hex, "x25519": x_hex, "self_sig": sig_hex}

    # Constant-deadline sleep: cap residual timing variance between the
    # row-exists and no-row paths (T-N2 / L6).
    elapsed = time.monotonic() - started
    remaining = _DIRECTORY_TIMING_BUDGET_S - elapsed
    if remaining > 0:
        await asyncio.sleep(remaining)
    return jsonify(body), 200


@users_bp.route("/enrolled", methods=["GET"])
@require_auth
async def list_enrolled():
    """List enrolled users (those with a usable X25519 key), paginated.

    Query params: ``limit`` (default 50, max 200), ``offset`` (default 0),
    mirroring ``list_files``. Each entry carries the username plus the
    public Ed25519 / X25519 keys and the X25519 self-signature (all hex),
    so a publisher can verify each self-signature before wrapping.

    Returns ``{"users": [...], "limit": int, "offset": int}``.

    Privacy: this discloses usernames + public keys to any authenticated
    user. That is inherent to a directory and the keys are public by
    definition (accepted leakage, design §5.6).
    """
    state = app_state()
    current_identity()

    try:
        raw_limit = request.args.get("limit", str(_DEFAULT_ENROLLED_LIMIT))
        raw_offset = request.args.get("offset", "0")
        limit = int(raw_limit)
        offset = int(raw_offset)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid request"}), 400
    if limit < 1 or limit > _MAX_ENROLLED_LIMIT or offset < 0:
        return jsonify({"error": "Invalid request"}), 400

    # list_enrolled_users returns the full enrolled set ordered by
    # username; page it at the HTTP layer (the set is bounded by the user
    # population and the DB query already filters to usable rows).
    enrolled = await asyncio.to_thread(state.db.list_enrolled_users)
    page = enrolled[offset : offset + limit]

    users = [
        {
            "username": entry["username"],
            "ed25519": bytes(entry["ed25519_pubkey"]).hex(),
            "x25519": bytes(entry["x25519_pubkey"]).hex(),
            "self_sig": bytes(entry["x25519_self_sig"]).hex(),
        }
        for entry in page
    ]
    return jsonify({"users": users, "limit": limit, "offset": offset}), 200
