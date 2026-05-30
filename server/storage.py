# LocalCloud - Server Storage Engine
#
# Blob storage: staging uploads, finalization with integrity verification,
# chunked downloads, and garbage collection of expired staging.
# The server ONLY stores ciphertext — it never reads or transforms data.
#
# Security: All file_id and upload_id values are strictly validated as
# lowercase hex UUIDs. All filesystem paths are canonicalized and
# containment-checked. Content-type is enforced on uploads.

from __future__ import annotations

import asyncio
import contextlib
import errno
import hmac
import logging
import os
import re
import shutil
import stat
import tempfile
import time
import unicodedata
import uuid
from pathlib import Path
from typing import cast

from quart import Blueprint, Response, jsonify, request

from server.auth import _canonicalize_username, require_auth
from server.database import Database
from server.policy import check_file_access, check_file_ownership
from server.quota import check_quota, commit_usage, release_usage
from server.state import app_state, current_identity
from shared.crypto import blake2b_hash
from shared.exceptions import (
    AuthError,
    QuotaExceededError,
    StorageError,
)
from shared.models import (
    MAX_CHUNKS_PER_FILE,
    MAX_HEADER_BYTES,
    MAX_METADATA_BYTES,
)

logger = logging.getLogger("localcloud.storage")


class ConfigurationError(StorageError):
    """Static deployment misconfiguration detected at startup (H15)."""


# ──────────────────────────── Constants ────────────────────────────

# Strict pattern for file_id and upload_id: lowercase hex UUID (no hyphens) or UUID4
_SAFE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_SAFE_HEX_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# Disallow C0 control characters and DEL in filenames at upload_init.
# Newlines, tabs, embedded NULs and similar are never meaningful in a
# user-visible filename and have caused trouble in log scrapers, shells,
# and downstream consumers.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

# Maximum sane values (server-operational; wire-format limit is the
# distinct constant MAX_CHUNKS in shared.models). MAX_CHUNKS_PER_FILE is
# imported above and used by its real name.
_MAX_FILENAME_LEN = 255
_MAX_VISIBILITY = 2

# Unicode categories rejected in filenames (in addition to the C0 control
# regex). Bidirectional override codepoints and zero-width characters are
# rejected because they let an attacker spoof filename rendering in a
# client UI. Filenames are server-visible plaintext (README §4.2) but
# must remain non-deceptive.
# These exact codepoints MUST appear literally in source: they are the
# denylist itself. pylint's bidi/zero-width guards (designed to catch
# *hidden* malicious code) fire on this intentional security data, so we
# disable them for this block only — keeping the guards active everywhere
# else in the file.
# pylint: disable=bidirectional-unicode,invalid-character-zero-width-space
_FILENAME_REJECT_CODEPOINTS = frozenset(
    {
        "​",
        "‌",
        "‍",  # zero-width space / non-joiner / joiner
        " ",
        " ",  # line/paragraph separators
        "‪",
        "‫",
        "‬",  # bidi embedding/override
        "‭",
        "‮",
        "⁦",
        "⁧",
        "⁨",
        "⁩",  # isolates
        "﻿",  # BOM / ZWNBSP
    }
)
# pylint: enable=bidirectional-unicode,invalid-character-zero-width-space

# Per-user staging caps (K3): bound the disk that any one user can hold
# in the staging area before finalize, and the number of concurrent
# upload sessions they may open.
MAX_STAGING_BYTES_PER_USER = 4 * 1024 * 1024 * 1024  # 4 GiB
MAX_OPEN_UPLOADS_PER_USER = 16

# Minimum chunk size (except for the last chunk in a file). Prevents an
# attacker from forcing many tiny-chunk syscalls and DB rows per byte.
MIN_CHUNK_SIZE = 1024  # 1 KiB

# Username constraints used when validating a share target. Server's
# /api/auth/login enforces 255 here, but for sharing we keep it tighter
# since the value is also rendered server-side.
MAX_USERNAME_LEN = 64

# Wrapped-keys bounds for share_file (H17). The exact wire format is
# PUBKEY_LEN(32) + NONCE_LEN(24) + PAYLOAD_LEN(64) + TAG_LEN(16) = 136
# bytes; MIN matches so truncated bundles are rejected before they
# reach the DB. MAX leaves headroom for protocol evolution while
# capping abuse. (Round-4 M6)
MIN_WRAPPED_KEYS_BYTES = 136
MAX_WRAPPED_KEYS_BYTES = 4096

# Exact length of the v2 owner self-share bundle accepted by /self_keys
# (item 2A): PUBKEY(32) + NONCE(24) + PAYLOAD(64) + TAG(16) = 136. Unlike
# share_file's loose MIN..MAX range, the self-share endpoint validates the
# bundle is EXACTLY this size — there is no protocol-evolution headroom to
# leave for an ephemeral-static bundle of fixed shape.
SELF_KEYS_BUNDLE_BYTES = 136

# Pagination defaults / caps for list_files (medium fix).
DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200

# Maximum accepted size of a single uploaded chunk (ciphertext + AEAD
# overhead). Surfaced as a module-level constant so create_app can seed
# AppState.max_chunk_size from it; the value is not runtime-configurable.
DEFAULT_MAX_CHUNK_SIZE = 5 * 1024 * 1024  # 5 MiB

# ──────────────────────────── Blueprint ────────────────────────────

storage_bp = Blueprint("storage", __name__, url_prefix="/api/files")

# Module globals retained ONLY for the non-request-context paths: the
# periodic cleanup task (cleanup_expired_uploads / cleanup_orphan_staging_dirs)
# and _cleanup_staging run outside any Quart request, so they cannot read
# app_state(). init_storage populates these. Request handlers do NOT read
# them — they use the fully-typed app_state() instead (ARCH-H2).
_db: Database | None = None
_blob_dir: str = ""
_staging_dir: str = ""
_staging_expiry: int = 3600


def init_storage(
    db: Database,
    blob_dir: str,
    staging_dir: str,
    staging_expiry: int = 3600,
) -> None:
    """Initialize storage module with dependencies.

    H15: Asserts that ``blob_dir`` and ``staging_dir`` live on the same
    filesystem so that finalize can rename chunks atomically with
    ``os.replace``. If they are not, the deployment is rejected here at
    startup rather than crashing on the first finalize.
    """
    global _db, _blob_dir, _staging_dir, _staging_expiry
    _db = db
    _blob_dir = os.path.realpath(blob_dir)
    _staging_dir = os.path.realpath(staging_dir)
    _staging_expiry = staging_expiry

    try:
        blob_dev = os.stat(_blob_dir).st_dev
        staging_dev = os.stat(_staging_dir).st_dev
    except OSError as exc:
        raise ConfigurationError(
            f"Failed to stat blob_dir or staging_dir: {exc}"
        ) from exc
    if blob_dev != staging_dev:
        raise ConfigurationError(
            "blob_dir and staging_dir must be on the same filesystem "
            "(required for atomic os.replace at finalize)"
        )


# ──────────────────────────── Validation Helpers ────────────────────────────


def _validate_id(value: str, label: str = "ID") -> str:
    """Validate that a value is a safe identifier and CANONICALIZE.

    Accepts UUID4 with hyphens OR 32-char lowercase hex. Returns the
    canonical 32-char hex no-hyphens form so two different encodings
    (with vs without hyphens) cannot produce distinct filesystem paths
    or DB rows for the same logical ID. (Round-10 LOW #10)

    Prevents path traversal by enforcing a strict allowlist format.
    """
    if _SAFE_ID_RE.match(value):
        return value.replace("-", "")
    if _SAFE_HEX_ID_RE.match(value):
        return value
    raise ValueError(f"Invalid {label} format")


def _safe_path(base_dir: str, *components: str) -> str:
    """Build a path under ``base_dir``, rejecting traversal and symlinks.

    Two distinct defenses (SEC-M1):

    1. Containment: the ``realpath`` of the joined path must stay inside
       ``base_dir``. This catches ``..`` traversal and symlinks that point
       *outside* the data tree.
    2. No-symlink-components: every existing path component *under*
       ``base_dir`` must be a real file/dir, not a symlink — even one that
       resolves back inside ``base_dir``. A naive containment check passes
       such a link, but following it on read (``send_file``) or having it
       in the final write target is exactly the SEC-M1 gap. ``base_dir``
       itself is trusted (``init_storage`` ``realpath``-resolves it), so we
       only vet the components appended here.

    Raises:
        ValueError: traversal detected, or any appended component is a
            symlink.
    """
    joined = os.path.join(base_dir, *components)
    canonical = os.path.realpath(joined)
    # Defense 1 — containment. canonical must start with base_dir + sep.
    if not canonical.startswith(base_dir + os.sep) and canonical != base_dir:
        raise ValueError("Path traversal detected")

    # Defense 2 — reject symlink components. Walk each appended component on
    # the *lexical* path and lstat it (lstat does not dereference, so a
    # symlink shows up as S_ISLNK rather than its target). Non-existent
    # components are fine: a chunk path is vetted here before it is created,
    # so ENOENT on a not-yet-created leaf is expected and allowed. Any other
    # stat error (EACCES, ELOOP from a symlink loop already in an
    # intermediate component) is treated as unsafe and rejected.
    prefix = base_dir
    for component in components:
        prefix = os.path.join(prefix, component)
        try:
            st = os.lstat(prefix)
        except FileNotFoundError:
            # Leaf (or deeper) not created yet — nothing to follow.
            break
        except OSError as exc:
            raise ValueError("Unsafe path component") from exc
        if stat.S_ISLNK(st.st_mode):
            raise ValueError("Symlinked path component rejected")
    return canonical


def _validate_filename(filename: str) -> bool:
    """Return True iff ``filename`` is acceptable for storage.

    Enforces length, NFC normalization, no C0 controls, no path separator
    bytes, and no rendering-spoof codepoints (bidi overrides, zero-width
    chars). Filename is server-visible plaintext per the spec, but it must
    not be able to lie to a client UI.
    """
    if not filename or len(filename) > _MAX_FILENAME_LEN:
        return False
    normalized = unicodedata.normalize("NFC", filename)
    if normalized != filename:
        # Reject denormalized forms so two distinct strings cannot collide
        # on lookup or render identically after normalization.
        return False
    if _CONTROL_CHAR_RE.search(filename):
        return False
    if "/" in filename or "\\" in filename:
        return False
    for ch in filename:
        if ch in _FILENAME_REJECT_CODEPOINTS:
            return False
        # Category Cf = format characters (invisible directionality/joiners).
        # Category Zs = space separator (includes regular space which is
        # fine, but also NBSP U+00A0 and narrow NBSP U+202F which can be
        # used to spoof filename rendering). Allow only regular ASCII
        # space (0x20) from Zs. (Round-10 LOW #11)
        cat = unicodedata.category(ch)
        if cat == "Cf":
            return False
        if cat == "Zs" and ch != " ":
            return False
    return True


# ──────────────────────────── Upload API ────────────────────────────


@storage_bp.route("/upload/init", methods=["POST"])
@require_auth
async def upload_init():
    """Initialize a new upload session.

    Request: {"filename": str, "expected_chunks": int}
    Response: {"upload_id": str}
    """
    state = app_state()
    identity = current_identity()

    data = await request.get_json(silent=True)
    if not data or "filename" not in data or "expected_chunks" not in data:
        return jsonify({"error": "Invalid request"}), 400

    raw_filename = data["filename"]
    if not isinstance(raw_filename, str):
        return jsonify({"error": "Invalid request"}), 400
    if not _validate_filename(raw_filename):
        return jsonify({"error": "Invalid request"}), 400
    filename = raw_filename

    # expected_chunks is now MANDATORY (was optional). Required so the
    # min-chunk-size check at upload_chunk can identify the last chunk
    # and the finalize step can enforce the count. Otherwise a client
    # could ship 100k tiny chunks unbounded. (Round-2 H6)
    raw_expected = data.get("expected_chunks")
    if not isinstance(raw_expected, int) or isinstance(raw_expected, bool):
        return jsonify({"error": "Invalid request"}), 400
    expected_chunks = raw_expected
    if expected_chunks < 1 or expected_chunks > MAX_CHUNKS_PER_FILE:
        return jsonify({"error": "Invalid request"}), 400

    # K3: Cap concurrent staging sessions per user to bound parallel
    # disk-fill attacks. Counted against non-expired, non-finalizing rows.
    open_count = await asyncio.to_thread(state.db.count_open_uploads, identity.user_id)
    if open_count >= MAX_OPEN_UPLOADS_PER_USER:
        return jsonify({"error": "Too many open uploads"}), 429

    # Generate upload ID (server-generated, always safe). It MUST be in the
    # same canonical 32-char no-hyphen form _validate_id returns, so the
    # staging dir, the DB row, and the later chunk/finalize lookups (which
    # run upload_id through _validate_id, stripping hyphens) all agree on
    # the same key. A hyphenated str(uuid4()) would never match the
    # canonicalized lookup, so every chunk POST would 400.
    upload_id = uuid.uuid4().hex
    staging_path = _safe_path(state.staging_dir, upload_id)
    await asyncio.to_thread(os.makedirs, staging_path, mode=0o700, exist_ok=True)

    # Record in database — if this fails, clean up the staging directory
    # so it does not leak. Cleanup-task scans for DB rows, so an orphan
    # directory with no DB row would otherwise persist indefinitely.
    try:
        await asyncio.to_thread(
            state.db.create_staging_upload,
            upload_id=upload_id,
            owner_id=identity.user_id,
            filename=filename,
            expected_chunks=expected_chunks,
            expiry_seconds=state.staging_expiry,
        )
    except Exception:
        try:
            await asyncio.to_thread(shutil.rmtree, staging_path, True)
        except OSError:
            logger.warning(
                "Failed to clean up staging dir after DB error: %s", upload_id
            )
        raise

    return jsonify({"upload_id": upload_id}), 201


@storage_bp.route("/upload/<upload_id>/chunk/<int:chunk_index>", methods=["POST"])
@require_auth
async def upload_chunk(upload_id: str, chunk_index: int):
    """Upload a single encrypted chunk.

    Request body: raw ciphertext bytes (Content-Type: application/octet-stream)
    Response: {"chunk_hash": str}
    """
    state = app_state()
    identity = current_identity()

    # Validate IDs
    try:
        upload_id = _validate_id(upload_id, "upload_id")
    except ValueError:
        return jsonify({"error": "Invalid request"}), 400

    # Enforce content-type (#11)
    content_type = request.content_type or ""
    if not content_type.startswith("application/octet-stream"):
        return jsonify({"error": "Invalid content type"}), 415

    # Validate chunk_index range (#17)
    if chunk_index < 0 or chunk_index >= MAX_CHUNKS_PER_FILE:
        return jsonify({"error": "Invalid request"}), 400

    # Verify upload exists and belongs to this user
    upload = await asyncio.to_thread(state.db.get_staging_upload, upload_id)
    if upload is None or upload["owner_id"] != identity.user_id:
        return jsonify({"error": "Invalid request"}), 400

    # Refuse new chunks once finalize has claimed this upload (#H19).
    # Without this, a slow chunk write could rename into the just-
    # renamed-away staging dir under the wrong path, or — worse —
    # land inside `<blob_dir>/<file_id>/N.bin` and clobber a
    # legitimate chunk in the finalized file. (Round-3 H3)
    if upload.get("finalizing", 0):
        return jsonify({"error": "Upload finalizing"}), 410

    # Reject chunk_index >= expected_chunks so an attacker can't write
    # 100k tiny chunks to arbitrary indices for a 3-chunk upload
    # (inode-exhaustion + per-row DB cost). (Round-3 M6)
    expected_chunks = upload.get("expected_chunks")
    if expected_chunks is not None and chunk_index >= expected_chunks:
        return jsonify({"error": "Invalid request"}), 400

    # #5: Enforce upload expiry at request time
    if time.time() > upload["expires_at"]:
        return jsonify({"error": "Upload expired"}), 410

    # Read chunk data
    # quart's Request.get_data is annotated `-> str | bytes` with no
    # @overload on `as_text`, so the type checker can't narrow on the
    # literal. With as_text=False the runtime contract is always bytes;
    # cast is a no-op at runtime and documents that invariant for the
    # downstream blake2b_hash / _write_file_bytes calls (both want bytes).
    chunk_data = cast(bytes, await request.get_data(as_text=False))
    if not chunk_data:
        return jsonify({"error": "Empty chunk"}), 400

    if len(chunk_data) > state.max_chunk_size:
        return jsonify({"error": "Chunk too large"}), 413

    # Medium: minimum chunk size for all but the last chunk. The last
    # chunk's size is determined by file length so it may be smaller.
    # `expected_chunks` was looked up above; we re-use that binding.
    if (
        expected_chunks is not None
        and chunk_index < expected_chunks - 1
        and len(chunk_data) < MIN_CHUNK_SIZE
    ):
        return jsonify({"error": "Chunk too small"}), 400

    # Per-user quota gating happens transactionally with the chunk
    # insert so two parallel uploads from the same user cannot both
    # pass the snapshot check and then both write their chunks past
    # the limit. Previously this was acknowledged as a "coarse DoS
    # bound"; README §4.2 actually mandates atomic quota accounting,
    # so we tighten it here. (Round-2 H2/H3)
    new_chunk_size = len(chunk_data)
    chunk_hash = blake2b_hash(chunk_data).hex()
    chunk_path = _safe_path(state.staging_dir, upload_id, f"{chunk_index}.bin")

    # Phase 1: write to disk OUTSIDE the DB lock so concurrent uploads
    # don't serialize on disk I/O. _write_file_bytes is itself atomic
    # (tempfile + fsync + replace) so a crash mid-write doesn't leave
    # a half-written chunk with a recorded hash.
    try:
        await asyncio.to_thread(_write_file_bytes, chunk_path, chunk_data)
    except OSError as exc:
        logger.warning(
            "chunk write failed for upload_id=%s idx=%d: %s",
            upload_id,
            chunk_index,
            exc,
        )
        return jsonify({"error": "Upload failed"}), 500

    # Phase 2: transactional check-and-insert. If quota is blown,
    # remove the just-written chunk from disk.
    def _check_and_insert() -> tuple[bool, str]:
        with state.db.transaction():
            used, quota = state.db.get_user_usage(identity.user_id)
            staging = state.db.get_total_staging_bytes(identity.user_id)
            if used + staging + new_chunk_size > quota:
                return False, "Quota exceeded"
            if staging + new_chunk_size > MAX_STAGING_BYTES_PER_USER:
                return False, "Staging quota exceeded"
            state.db.add_staging_chunk(
                upload_id=upload_id,
                chunk_index=chunk_index,
                chunk_hash=chunk_hash,
                chunk_size=new_chunk_size,
            )
            return True, ""

    ok, err_msg = await asyncio.to_thread(_check_and_insert)
    if not ok:
        # Roll back the disk write so the chunk doesn't accrue.
        with contextlib.suppress(OSError):
            await asyncio.to_thread(os.unlink, chunk_path)
        return jsonify({"error": err_msg}), 413

    return jsonify({"chunk_hash": chunk_hash}), 200


@storage_bp.route("/upload/<upload_id>/finalize", methods=["POST"])
@require_auth
async def upload_finalize(upload_id: str):
    """Finalize an upload: verify integrity, check quota, commit.

    Request: {
        "file_id": str,
        "total_chunks": int,
        "file_header": str (hex),
        "encrypted_metadata": str (hex),
        "visibility": int,
        "expected_hashes": [str]
    }
    Response: {"file_id": str} on success
    """
    state = app_state()
    identity = current_identity()

    # Validate upload_id
    try:
        upload_id = _validate_id(upload_id, "upload_id")
    except ValueError:
        return jsonify({"error": "Invalid request"}), 400

    data = await request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    # Verify upload exists and belongs to this user
    upload = await asyncio.to_thread(state.db.get_staging_upload, upload_id)
    if upload is None or upload["owner_id"] != identity.user_id:
        return jsonify({"error": "Invalid request"}), 400

    # #5: Enforce upload expiry at request time
    if time.time() > upload["expires_at"]:
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Upload expired"}), 410

    # Strict type-check each field rather than relying on int()/str()
    # coercion (which would accept ints-as-strings, bools-as-ints,
    # etc.). (Round-3 H4 / H5)
    raw_file_id = data.get("file_id")
    if not isinstance(raw_file_id, str):
        return jsonify({"error": "Invalid request"}), 400
    file_id = raw_file_id
    try:
        file_id = _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Invalid request"}), 400

    raw_total_chunks = data.get("total_chunks")
    if not isinstance(raw_total_chunks, int) or isinstance(raw_total_chunks, bool):
        return jsonify({"error": "Invalid request"}), 400
    total_chunks = raw_total_chunks
    if total_chunks < 1 or total_chunks > MAX_CHUNKS_PER_FILE:
        return jsonify({"error": "Invalid request"}), 400

    raw_visibility = data.get("visibility", 0)
    if not isinstance(raw_visibility, int) or isinstance(raw_visibility, bool):
        return jsonify({"error": "Invalid request"}), 400
    visibility = raw_visibility
    if visibility < 0 or visibility > _MAX_VISIBILITY:
        return jsonify({"error": "Invalid request"}), 400

    try:
        file_header = bytes.fromhex(data.get("file_header", ""))
        encrypted_metadata = bytes.fromhex(data.get("encrypted_metadata", ""))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid request"}), 400

    if not file_header or not encrypted_metadata:
        return jsonify({"error": "Invalid request"}), 400

    # Per-field size caps. MAX_CONTENT_LENGTH (5 MiB) bounds the whole
    # request, but without per-field caps an attacker could store a
    # 2.5 MiB file_header + 2.5 MiB encrypted_metadata BLOB in the DB.
    # The wire-format contract is MAX_HEADER_BYTES=4096 and
    # MAX_METADATA_BYTES=65536. (Round-4 H1)
    if len(file_header) > MAX_HEADER_BYTES:
        return jsonify({"error": "Invalid request"}), 400
    if len(encrypted_metadata) > MAX_METADATA_BYTES:
        return jsonify({"error": "Invalid request"}), 400

    if (
        upload["expected_chunks"] is not None
        and total_chunks != upload["expected_chunks"]
    ):
        return jsonify({"error": "Invalid request"}), 400

    # Claim the staging row before reading chunks — wire H19 protection
    # that was previously dead code. Until this transaction commits, the
    # background cleanup task cannot delete the staging row out from under
    # us. The `finalizing = 1` flag remains set if we fail; _cleanup_staging
    # deletes by upload_id regardless of the flag so a failed finalize
    # still releases the row.
    def _claim_finalizing() -> bool:
        with state.db.transaction():
            return state.db.mark_upload_finalizing(upload_id)

    try:
        claimed = await asyncio.to_thread(_claim_finalizing)
    except Exception:
        logger.exception("Failed to claim staging upload for finalize")
        return jsonify({"error": "Upload failed"}), 500
    if not claimed:
        # Already finalizing in another request, or row was deleted by
        # an earlier expiry sweep that won the race.
        return jsonify({"error": "Upload expired"}), 410

    # Verify chunk count matches
    staged_chunks = await asyncio.to_thread(state.db.get_staging_chunks, upload_id)
    if len(staged_chunks) != total_chunks:
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Invalid request"}), 400

    # Verify chunk indices are contiguous 0..total_chunks-1
    chunk_indices = {c["chunk_index"] for c in staged_chunks}
    if chunk_indices != set(range(total_chunks)):
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Invalid request"}), 400

    expected_hashes = data.get("expected_hashes")
    if not expected_hashes or not isinstance(expected_hashes, list):
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Invalid request"}), 400

    if len(expected_hashes) != total_chunks:
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Invalid request"}), 400

    # Constant-time per-chunk hash comparison. The hashes are public to
    # both ends so a naive `!=` is not catastrophic — but using
    # compare_digest closes a latent timing channel that could probe a
    # known-plaintext exfiltration in a hostile-client scenario.
    for chunk, expected in zip(staged_chunks, expected_hashes, strict=True):
        if not isinstance(expected, str) or len(expected) != len(chunk["chunk_hash"]):
            await asyncio.to_thread(_cleanup_staging, upload_id)
            return jsonify({"error": "Invalid request"}), 400
        if not hmac.compare_digest(chunk["chunk_hash"], expected):
            await asyncio.to_thread(_cleanup_staging, upload_id)
            return jsonify({"error": "Invalid request"}), 400

    # Atomic-commit finalize using directory rename.
    #
    # The staging directory has filename `<upload_id>` and holds all
    # chunks indexed by `<i>.bin`. The blob directory will be
    # `<file_id>`. Since blob_dir and staging_dir are required to be on
    # the same filesystem (asserted in init_storage), renaming the whole
    # directory is a single atomic FS operation — replacing the per-
    # chunk move loop, which left partial state on crash or partial-
    # write failure.
    blob_path = _safe_path(state.blob_dir, file_id)
    src_dir = _safe_path(state.staging_dir, upload_id)

    total_bytes = sum(c["chunk_size"] for c in staged_chunks)
    total_bytes += len(encrypted_metadata) + len(file_header)

    def _commit_finalize():
        # Phase 1: atomic directory rename. os.rename refuses to clobber
        # an existing directory destination (errno=ENOTEMPTY/EEXIST on
        # Linux), so a file_id collision fails here without ever touching
        # the existing blob.
        try:
            os.rename(src_dir, blob_path)
        except FileExistsError as exc:
            raise StorageError("file_id collision") from exc
        except OSError as exc:
            # Linux returns ENOTEMPTY for rename-onto-existing-non-empty
            # directory, surfaced as OSError; treat both as collision.
            if exc.errno in (errno.EEXIST, errno.ENOTEMPTY, errno.EXDEV):
                raise StorageError("file_id collision") from exc
            raise

        # Phase 2: DB commit. We do create_file + commit_usage + the
        # staging-row delete in ONE transaction so a crash anywhere
        # in between leaves the DB consistent. Previously
        # delete_staging_upload was outside the transaction, leaving
        # a finalizing=1 row wedged for 1 hour if anything went wrong
        # between commit and that call. (Round-3 H2)
        try:
            with state.db.transaction() as _conn:
                check_quota(state.db, identity.user_id, total_bytes)
                state.db.create_file(
                    file_id=file_id,
                    owner_id=identity.user_id,
                    filename=upload["filename"],
                    visibility=visibility,
                    total_chunks=total_chunks,
                    total_bytes=total_bytes,
                    encrypted_metadata=encrypted_metadata,
                    file_header=file_header,
                )
                commit_usage(state.db, identity.user_id, total_bytes)
                _conn.execute(
                    "DELETE FROM staging_uploads WHERE upload_id = ?",
                    (upload_id,),
                )
        except Exception:
            # Undo the rename: move blob_path back. If THIS fails we
            # have a real orphan — log it loudly.
            try:
                os.rename(blob_path, src_dir)
            except OSError:
                logger.error(
                    "ORPHAN BLOB: rolled-back finalize left "
                    "blob_path=%s with no DB record",
                    blob_path,
                )
            raise

    try:
        await asyncio.to_thread(_commit_finalize)
    except QuotaExceededError:
        return jsonify({"error": "Quota exceeded"}), 413
    except StorageError as exc:
        # Known collision — surfaced as 409.
        logger.info("Finalize rejected: %s (upload_id=%s)", exc, upload_id)
        return jsonify({"error": "Invalid request"}), 409
    except Exception:
        logger.exception(
            "Finalize failed for upload_id=%s file_id=%s",
            upload_id,
            file_id,
        )
        return jsonify({"error": "Upload failed"}), 500

    return jsonify({"file_id": file_id}), 201


# ──────────────────────────── Download API ────────────────────────────


@storage_bp.route("/<file_id>", methods=["GET"])
@require_auth
async def get_file_metadata(file_id: str):
    """Get file metadata (header + encrypted metadata blob).

    Does NOT include the server-internal owner_id. The owner's pinned
    Ed25519 public key — which is what the client actually needs for
    signature verification — is served separately at /owner_pubkey.
    """
    state = app_state()
    identity = current_identity()

    try:
        file_id = _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        file_record = await asyncio.to_thread(
            check_file_access, state.db, file_id, identity.user_id
        )
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    is_owner = file_record["owner_id"] == identity.user_id
    body: dict = {
        "file_id": file_record["file_id"],
        "filename": file_record["filename"],
        "total_chunks": file_record["total_chunks"],
        "file_header": (
            file_record["file_header"].hex()
            if isinstance(file_record["file_header"], bytes)
            else file_record["file_header"]
        ),
        "encrypted_metadata": (
            file_record["encrypted_metadata"].hex()
            if isinstance(file_record["encrypted_metadata"], bytes)
            else file_record["encrypted_metadata"]
        ),
        "visibility": file_record["visibility"],
    }
    # Only expose total_bytes to the owner — for non-owners (shared and
    # public files) this would leak per-file padded-ciphertext sizes
    # across users. (#H9 metadata leak)
    if is_owner:
        body["total_bytes"] = file_record["total_bytes"]
    return jsonify(body), 200


@storage_bp.route("/<file_id>/owner_pubkey", methods=["GET"])
@require_auth
async def get_owner_pubkey(file_id: str):
    """Return the owner's Ed25519 identity public key for signature
    verification of shared or public files. (H17 — wires the dead
    `get_owner_ed25519_pubkey` DB method to a route.)

    Returns ``{"pubkey": <hex>}`` with empty string if the owner has not
    yet registered a key. 404 for unknown / inaccessible files (same as
    metadata endpoint, no enumeration distinction).
    """
    state = app_state()
    identity = current_identity()

    try:
        file_id = _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    # Authorization: caller must have access to the file before we
    # disclose the owner's pubkey (which is publishing-by-implication).
    try:
        await asyncio.to_thread(check_file_access, state.db, file_id, identity.user_id)
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    pubkey = await asyncio.to_thread(state.db.get_owner_ed25519_pubkey, file_id)
    if pubkey is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"pubkey": pubkey.hex()}), 200


@storage_bp.route("/<file_id>/chunk/<int:chunk_index>", methods=["GET"])
@require_auth
async def get_chunk(file_id: str, chunk_index: int):
    """Download a single encrypted chunk (ciphertext only)."""
    state = app_state()
    identity = current_identity()

    # Validate file_id format (#1)
    try:
        file_id = _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        file_record = await asyncio.to_thread(
            check_file_access, state.db, file_id, identity.user_id
        )
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    if chunk_index < 0 or chunk_index >= file_record["total_chunks"]:
        return jsonify({"error": "Not found"}), 404

    # Build and validate path (#1)
    chunk_path = _safe_path(state.blob_dir, file_id, f"{chunk_index}.bin")

    # Read the chunk through an O_NOFOLLOW fd (in a worker thread) and
    # return a plain Response. Two reasons we do NOT use send_file here:
    #
    #   1. O_NOFOLLOW closes the TOCTOU window after _safe_path's lstat
    #      check — if a symlink is swapped in at the final component
    #      between the check and the open, open() fails atomically
    #      (ELOOP) instead of following the link, and the helper maps
    #      both ELOOP and ENOENT to 404. send_file would open and follow.
    #   2. A plain Response emits NO ETag / Last-Modified header, so the
    #      per-chunk on-disk ingestion timestamp never leaks to the
    #      client (#H13 metadata leak). The old send_file call tried to
    #      suppress those headers via last_modified=None/conditional=
    #      False/etag=... but `etag` is not even a valid parameter on the
    #      installed Quart (it is `add_etags`), so that call raised
    #      TypeError at runtime.
    #
    # The chunk (<= ~4 MiB on the wire) is read fully into memory; a
    # streaming read is a possible Phase 4 optimization.
    try:
        data = await asyncio.to_thread(_read_blob_chunk_nofollow, Path(chunk_path))
    except FileNotFoundError:
        return jsonify({"error": "Not found"}), 404
    response = Response(data, mimetype="application/octet-stream")
    response.headers["Cache-Control"] = "no-store, private"
    return response


# ──────────────────────────── Delete ────────────────────────────


@storage_bp.route("/<file_id>", methods=["DELETE"])
@require_auth
async def delete_file(file_id: str):
    """Delete a file and release quota. Only the owner can delete.

    #7: DB-first ordering — delete metadata and release quota in a
    transaction first, then clean up filesystem. If FS cleanup fails,
    orphaned blobs are harmless (no metadata pointing to them).
    """
    state = app_state()
    identity = current_identity()

    # Validate file_id format (#1)
    try:
        file_id = _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        await asyncio.to_thread(
            check_file_ownership, state.db, file_id, identity.user_id
        )
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    # Quota race fix (#5/#6): delete and release inside the same
    # transaction, using the authoritative byte count returned by
    # delete_file. If another request wins the race and deletes the row
    # first, this delete_file returns None and we MUST NOT release_usage
    # — doing so would let a user inflate their effective quota by
    # double-deleting the same file.
    def _db_delete() -> int | None:
        with state.db.transaction():
            deleted_bytes = state.db.delete_file(file_id)
            if deleted_bytes is not None:
                release_usage(state.db, identity.user_id, deleted_bytes)
            return deleted_bytes

    deleted_bytes = await asyncio.to_thread(_db_delete)

    # Phase 2: Filesystem cleanup (best-effort after DB commit). Even on
    # idempotent re-delete (deleted_bytes is None) we attempt blob
    # cleanup in case the first delete left orphans.
    blob_path = _safe_path(state.blob_dir, file_id)
    try:
        if await asyncio.to_thread(os.path.isdir, blob_path):
            await asyncio.to_thread(shutil.rmtree, blob_path)
    except OSError:
        logger.warning("Failed to clean up blob dir: %s", file_id)

    # Idempotent response: both first delete and a redundant follow-up
    # return 200. This matches REST DELETE semantics and avoids leaking
    # whether the file existed at the moment we entered the handler.
    _ = deleted_bytes
    return jsonify({"status": "deleted"}), 200


# ──────────────────────────── List Files ────────────────────────────


@storage_bp.route("", methods=["GET"])
@require_auth
async def list_files():
    """List files accessible to the authenticated user, paginated.

    Query params: ``limit`` (default 50, max 200), ``offset`` (default 0).
    Returns ``{"files": [...], "limit": int, "offset": int}``.

    Per-file ``total_bytes`` is suppressed for files the caller does not
    own — leaking padded-ciphertext sizes across users would be a
    metadata-leak (#H9).
    """
    state = app_state()
    identity = current_identity()

    # Parse pagination params with strict bounds.
    try:
        raw_limit = request.args.get("limit", str(DEFAULT_LIST_LIMIT))
        raw_offset = request.args.get("offset", "0")
        limit = int(raw_limit)
        offset = int(raw_offset)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid request"}), 400
    if limit < 1 or limit > MAX_LIST_LIMIT or offset < 0:
        return jsonify({"error": "Invalid request"}), 400

    files = await asyncio.to_thread(
        state.db.list_user_files,
        identity.user_id,
        limit,
        offset,
    )
    caller_id = identity.user_id
    result = []
    for f in files:
        is_owner = f["owner_id"] == caller_id
        entry: dict = {
            "file_id": f["file_id"],
            "filename": f["filename"],
            "total_chunks": f["total_chunks"],
            "visibility": f["visibility"],
            "created_at": f["created_at"],
        }
        if is_owner:
            entry["total_bytes"] = f["total_bytes"]
        result.append(entry)

    return (
        jsonify(
            {
                "files": result,
                "limit": limit,
                "offset": offset,
            }
        ),
        200,
    )


# ──────────────────────────── Sharing ────────────────────────────


@storage_bp.route("/<file_id>/share", methods=["POST"])
@require_auth
async def share_file(file_id: str):
    """Share a file with another user by uploading wrapped keys.

    Response is uniform — `{"status": "shared"}` (200) — regardless of
    whether the target username exists or whether the call is otherwise
    a no-op. This closes the share-endpoint username-enumeration oracle
    (#H1) that previously returned 400 for unknown targets and 200 for
    known ones.
    """
    state = app_state()
    identity = current_identity()

    try:
        file_id = _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        await asyncio.to_thread(
            check_file_ownership, state.db, file_id, identity.user_id
        )
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    data = await request.get_json(silent=True)
    if not data or "shared_with" not in data or "wrapped_keys" not in data:
        return jsonify({"error": "Invalid request"}), 400

    raw_target = data["shared_with"]
    if not isinstance(raw_target, str):
        return jsonify({"error": "Invalid request"}), 400
    if not raw_target or len(raw_target) > MAX_USERNAME_LEN:
        return jsonify({"error": "Invalid request"}), 400
    # Canonicalize the target so a share targeted at "Alice" or
    # fullwidth "ＡＬＩＣＥ" lands on the same row as the canonical
    # "alice". Otherwise the operator could see a 200 status but the
    # DB lookup would silently miss (and the dummy timing path would
    # run), giving a false success signal. (Round-4 H2)
    try:
        target_username = _canonicalize_username(raw_target)
    except Exception:
        # Canonicalize raised — treat as not-found (uniform timing-
        # equalized path).
        target_username = None

    try:
        wrapped_keys = bytes.fromhex(data["wrapped_keys"])
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid request"}), 400
    if not (MIN_WRAPPED_KEYS_BYTES <= len(wrapped_keys) <= MAX_WRAPPED_KEYS_BYTES):
        return jsonify({"error": "Invalid request"}), 400

    # Start the timing budget BEFORE the username lookup so its latency
    # is also inside the constant-deadline envelope. The user-row fetch
    # touches BLOB columns (ed25519_pubkey, password_hash) for existing
    # users vs an empty index probe for unknown users — otherwise that
    # delta leaks outside the budget. (Round-7 M3)
    started = time.monotonic()

    # Look up target — but if missing, run an EQUIVALENT amount of DB
    # work in the same shape (BEGIN IMMEDIATE + write tx + lock-take)
    # so an attacker can't enumerate via lock contention or fsync tail.
    # (Round-7 H1/H2)
    target_user = (
        await asyncio.to_thread(state.db.get_user_by_username, target_username)
        if target_username is not None
        else None
    )
    is_self_share = (
        target_user is not None and target_user["user_id"] == identity.user_id
    )
    do_real_work = target_user is not None and not is_self_share
    # Snapshot the share target's id while the None-narrowing is visible
    # to the type checker; the closure below only reads it on the
    # do_real_work branch (which implies target_user is not None).
    target_user_id = target_user["user_id"] if target_user is not None else ""

    def _db_share_or_dummy():
        # Both branches enter a write transaction so they contend on
        # Database._lock + SQLite reserved-lock identically, AND both
        # commit a WAL frame so fsync tail latency hits both alike.
        # The constant-deadline sleep at the end caps any residual
        # variance.
        with state.db.transaction() as conn:
            if do_real_work:
                state.db.add_file_share(
                    file_id=file_id,
                    shared_with_id=target_user_id,
                    wrapped_keys=wrapped_keys,
                )
                conn.execute(
                    "UPDATE files SET visibility = MAX(visibility, 1) "
                    "WHERE file_id = ? AND visibility = 0",
                    (file_id,),
                )
            else:
                # Idempotent no-op UPDATEs against the same hot rows.
                # SQLite still emits a WAL frame for these (verified
                # empirically — `SET col = col` is NOT short-circuited).
                # Lock acquisition + fsync therefore happens in both
                # branches; subsequent constant-deadline sleep caps the
                # remaining sub-millisecond variance.
                conn.execute(
                    "UPDATE files SET file_id = file_id WHERE file_id = ?",
                    (file_id,),
                )
                conn.execute(
                    "UPDATE users SET user_id = user_id WHERE user_id = ?",
                    (identity.user_id,),
                )

    await asyncio.to_thread(_db_share_or_dummy)
    # Constant-deadline sleep: response time is dominated by the
    # 150 ms wall-clock budget. The combination of (a) identical
    # write-transaction shape between branches and (b) this constant
    # cap is what closes the timing oracle even under WAL fsync tail
    # or lock contention. (Round-7 H1)
    _SHARE_TIMING_BUDGET_S = 0.150
    elapsed = time.monotonic() - started
    remaining = _SHARE_TIMING_BUDGET_S - elapsed
    if remaining > 0:
        await asyncio.sleep(remaining)
    return jsonify({"status": "shared"}), 200


@storage_bp.route("/<file_id>/share/<recipient_username>", methods=["DELETE"])
@require_auth
async def unshare_file(file_id: str, recipient_username: str):
    """Revoke a previously-granted share.

    Server-side revocation only: deletes the wrapped-keys row so the
    recipient can no longer fetch keys via ``/wrapped_keys``. A
    recipient who already downloaded the wrapped bundle retains the
    plaintext keys offline — to force key rotation the owner must
    re-upload under a new ``file_key``. (Round-2 H9)

    Idempotent like other DELETE endpoints. Response shape matches
    /share/POST: ``{"status": "unshared"}``. Returns 200 even if the
    target user / share row doesn't exist (no enumeration oracle).
    """
    state = app_state()
    identity = current_identity()

    try:
        file_id = _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        await asyncio.to_thread(
            check_file_ownership,
            state.db,
            file_id,
            identity.user_id,
        )
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    if not recipient_username or len(recipient_username) > MAX_USERNAME_LEN:
        return jsonify({"error": "Invalid request"}), 400

    # Canonicalize the recipient (NFKC + casefold) for the same reason
    # share_file does — otherwise "Alice" would not match the registered
    # "alice" and the dummy path would run unnoticed. (Round-4 H2)
    try:
        canon_recipient = _canonicalize_username(recipient_username)
    except Exception:
        canon_recipient = None

    # Start the timing budget BEFORE the username lookup so its
    # latency is inside the constant-deadline envelope. (Round-7 M3)
    started = time.monotonic()

    target_user = (
        await asyncio.to_thread(state.db.get_user_by_username, canon_recipient)
        if canon_recipient is not None
        else None
    )
    # Snapshot the recipient id while None-narrowing is visible to the
    # type checker; the closure's real branch implies target_user is set.
    target_user_id = target_user["user_id"] if target_user is not None else ""

    def _db_unshare_or_dummy():
        # Both branches enter a write transaction (BEGIN IMMEDIATE) so
        # they contend on Database._lock + SQLite reserved-lock
        # identically, and both commit a WAL frame so fsync tail hits
        # both. (Round-7 H1/H2)
        with state.db.transaction() as conn:
            if target_user is not None:
                state.db.remove_file_share(
                    file_id=file_id,
                    shared_with_id=target_user_id,
                )
                # If no shares remain AND the file isn't public,
                # downgrade visibility back to PRIVATE so the server
                # access policy matches the lack of share rows.
                remaining_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM file_shares " "WHERE file_id = ?",
                    (file_id,),
                ).fetchone()
                if remaining_row and remaining_row["cnt"] == 0:
                    conn.execute(
                        "UPDATE files SET visibility = 0 "
                        "WHERE file_id = ? AND visibility = 1",
                        (file_id,),
                    )
            else:
                conn.execute(
                    "UPDATE files SET file_id = file_id WHERE file_id = ?",
                    (file_id,),
                )
                conn.execute(
                    "UPDATE users SET user_id = user_id WHERE user_id = ?",
                    (identity.user_id,),
                )

    await asyncio.to_thread(_db_unshare_or_dummy)
    _SHARE_TIMING_BUDGET_S = 0.150
    elapsed = time.monotonic() - started
    remaining = _SHARE_TIMING_BUDGET_S - elapsed
    if remaining > 0:
        await asyncio.sleep(remaining)
    return jsonify({"status": "unshared"}), 200


@storage_bp.route("/<file_id>/self_keys", methods=["POST"])
@require_auth
async def self_keys(file_id: str):
    """Register the OWNER's self-wrapped key bundle (item 2A).

    The owner wraps ``file_key``+``meta_key`` to their OWN X25519 key and
    POSTs the bundle here; it is stored as a self-share row in
    ``file_shares`` with ``shared_with_id == owner_id``. ``get_wrapped_keys``
    then returns this row to the owner exactly as for any recipient, so the
    owner and every recipient acquire keys through ONE fail-closed server
    path and no plaintext key ever touches disk (the old
    ``<file_id>.keys.json`` cache is removed).

    Distinct from ``POST /share``: ``/share`` is timing-equalized against an
    external username-enumeration oracle and deliberately routes a
    self-share to a no-op (it never writes a row for yourself). Registering
    a bundle to *yourself* has no username to enumerate, so this endpoint
    carries NO timing budget and NO username branch.

    The bundle is opaque AEAD to the server (it cannot unwrap it). The
    length is validated to be EXACTLY 136 bytes (PUBKEY 32 + NONCE 24 +
    PAYLOAD 64 + TAG 16) for this v2 ephemeral-static bundle — the loose
    136..4096 range used by ``/share`` is intentionally NOT applied here.

    Response is uniform with the other file endpoints: 404 for unknown /
    non-owned files (no existence oracle), 400 for a malformed body.
    """
    state = app_state()
    identity = current_identity()

    try:
        file_id = _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        await asyncio.to_thread(
            check_file_ownership, state.db, file_id, identity.user_id
        )
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    data = await request.get_json(silent=True)
    if not data or "wrapped_keys" not in data:
        return jsonify({"error": "Invalid request"}), 400

    raw = data["wrapped_keys"]
    if not isinstance(raw, str):
        return jsonify({"error": "Invalid request"}), 400
    try:
        wrapped_keys = bytes.fromhex(raw)
    except ValueError:
        return jsonify({"error": "Invalid request"}), 400
    # Exact length for the v2 ephemeral-static bundle — NOT the loose
    # /share range. A truncated or padded bundle is rejected before the DB.
    if len(wrapped_keys) != SELF_KEYS_BUNDLE_BYTES:
        return jsonify({"error": "Invalid request"}), 400

    def _db_store() -> None:
        with state.db.transaction():
            # shared_with == owner: the self-share row. INSERT OR REPLACE
            # makes re-registration (upload repair / migrate-keys) idempotent.
            state.db.add_file_share(
                file_id=file_id,
                shared_with_id=identity.user_id,
                wrapped_keys=wrapped_keys,
            )

    await asyncio.to_thread(_db_store)
    return jsonify({"status": "stored"}), 200


@storage_bp.route("/<file_id>/wrapped_keys", methods=["GET"])
@require_auth
async def get_wrapped_keys(file_id: str):
    """Get wrapped keys for the authenticated user.

    Returns the share row keyed on (file_id, caller). This is the SINGLE
    key-acquisition path: for a recipient it returns the per-recipient
    bundle; for the owner it returns the owner's self-share row registered
    via ``POST /self_keys`` (item 2A). There is NO owner special-casing —
    a plain (file_id, user_id) lookup serves both. ``null`` when no row
    exists (e.g. an owner who has not yet registered a self-share).
    """
    state = app_state()
    identity = current_identity()

    try:
        file_id = _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        await asyncio.to_thread(check_file_access, state.db, file_id, identity.user_id)
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    wrapped = await asyncio.to_thread(
        state.db.get_wrapped_keys, file_id, identity.user_id
    )
    if wrapped is None:
        return jsonify({"wrapped_keys": None}), 200

    return jsonify({"wrapped_keys": wrapped.hex()}), 200


# ──────────────────────────── Quota ────────────────────────────


@storage_bp.route("/quota", methods=["GET"])
@require_auth
async def get_quota():
    """Get quota information for the authenticated user."""
    state = app_state()
    identity = current_identity()
    from server.quota import get_quota_info

    info = await asyncio.to_thread(get_quota_info, state.db, identity.user_id)
    return jsonify(info), 200


# ──────────────────────────── Internal Helpers ────────────────────────────


def _read_blob_chunk_nofollow(chunk_path: Path) -> bytes:
    """Read a blob chunk via an O_NOFOLLOW fd so a symlink swapped in
    after the _safe_path check is rejected atomically at open() rather
    than followed. Raises FileNotFoundError if the chunk is absent or
    the final component is a symlink (ELOOP), so callers map both to 404.
    """
    try:
        fd = os.open(chunk_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ELOOP):
            raise FileNotFoundError(str(chunk_path)) from exc
        raise
    try:
        with os.fdopen(fd, "rb", closefd=True) as handle:
            return handle.read()
    except OSError as exc:
        raise FileNotFoundError(str(chunk_path)) from exc


def _write_file_bytes(path: str, data: bytes) -> None:
    """Write bytes to a file durably.

    Writes to a unique tempfile in the same directory, fsyncs, then
    atomically renames into place via ``os.replace``. Avoids the torn-
    write window where a crash between ``write`` and ``close`` would
    leave a truncated chunk on disk with a recorded BLAKE2b hash that
    no longer matches the bytes there.
    """
    directory = os.path.dirname(path)
    fd = None
    tmp_path: str | None = None
    try:
        # tempfile.mkstemp creates with mode 0o600 already (per stdlib
        # docs and POSIX), so no chmod is needed. (Round-8 INFO #4)
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".write-", suffix=".tmp")
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(tmp_path, path)
        tmp_path = None
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        if tmp_path is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)


def _cleanup_staging(upload_id: str) -> None:
    """Remove staging directory and database records for an upload.

    Validates upload_id format up front; invalid input is treated as a
    no-op (no FS or DB action). All FS errors are logged and swallowed
    so the DB row is always released — orphan directories will be
    cleaned by the next cleanup pass via cross-reference (#52 fix).
    """
    assert _db is not None
    try:
        upload_id = _validate_id(upload_id, "upload_id")
    except ValueError:
        return

    try:
        staging_path = _safe_path(_staging_dir, upload_id)
        if os.path.isdir(staging_path):
            shutil.rmtree(staging_path)
    except (ValueError, OSError) as exc:
        logger.warning("Failed FS cleanup for upload_id=%s: %s", upload_id, exc)
    try:
        _db.delete_staging_upload(upload_id)
    except Exception:
        logger.exception("Failed DB cleanup for upload_id=%s", upload_id)


def cleanup_expired_uploads() -> int:
    """Garbage collect expired staging uploads. Returns count cleaned.

    Per-upload errors are logged and the loop continues — a single
    transient FS failure must not block the rest of the cleanup pass
    (#85 fix).
    """
    assert _db is not None
    try:
        expired = _db.cleanup_expired_staging()
    except Exception:
        logger.exception("cleanup_expired_staging failed")
        return 0
    for upload_id in expired:
        try:
            staging_path = _safe_path(_staging_dir, upload_id)
            if os.path.isdir(staging_path):
                shutil.rmtree(staging_path)
        except (ValueError, OSError) as exc:
            logger.warning("cleanup failed for upload_id=%s: %s", upload_id, exc)
    return len(expired)


def cleanup_orphan_staging_dirs() -> int:
    """Scan the staging directory and remove any subdirectory that has
    no corresponding row in ``staging_uploads``. Closes the orphan-dir
    leak where ``upload_init``'s DB insert failed AFTER ``os.makedirs``
    succeeded (#20 fix).

    Returns the number of orphan directories removed.
    """
    assert _db is not None
    if not _staging_dir or not os.path.isdir(_staging_dir):
        return 0
    removed = 0
    try:
        entries = os.listdir(_staging_dir)
    except OSError as exc:
        logger.warning("cleanup_orphan_staging_dirs listdir failed: %s", exc)
        return 0
    for name in entries:
        # Only treat strictly-validated UUIDs as upload IDs; ignore
        # everything else (foreign files an operator may have placed).
        if not (_SAFE_ID_RE.match(name) or _SAFE_HEX_ID_RE.match(name)):
            continue
        upload = None
        try:
            upload = _db.get_staging_upload(name)
        except Exception:
            logger.exception("orphan scan: DB lookup failed for %s", name)
            continue
        if upload is not None:
            continue
        try:
            staging_path = _safe_path(_staging_dir, name)
            if os.path.isdir(staging_path):
                shutil.rmtree(staging_path)
                removed += 1
        except (ValueError, OSError) as exc:
            logger.warning("orphan dir cleanup failed %s: %s", name, exc)
    return removed
