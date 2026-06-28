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
import sqlite3
import stat
import tempfile
import time
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from quart import Blueprint, Response, jsonify, request

from server.auth import _canonicalize_username, require_auth
from server.database import Database
from server.policy import check_file_access, check_file_ownership
from server.quota import check_quota, commit_usage, release_usage
from server.state import AppState, app_state, current_identity
from server.timing import sleep_until_deadline
from shared.crypto import blake2b_hash
from shared.exceptions import (
    AuthError,
    QuotaExceededError,
    StorageError,
)
from shared.file_ids import canonicalize_file_id, is_canonical_id
from shared.models import (
    MAX_CHUNKS_PER_FILE,
    MAX_HEADER_BYTES,
    MAX_METADATA_BYTES,
    Visibility,
)

logger = logging.getLogger("localcloud.storage")


class ConfigurationError(StorageError):
    """Static deployment misconfiguration detected at startup (H15)."""


# ──────────────────────────── Constants ────────────────────────────

# file_id / upload_id format + canonicalization now lives in
# shared.file_ids (canonicalize_file_id / is_canonical_id), shared with the
# client (Phase 3B dedup). _validate_id below wraps it to keep this module's
# label-bearing, ValueError-raising contract.

# Disallow C0 control characters and DEL in filenames at upload_init.
# Newlines, tabs, embedded NULs and similar are never meaningful in a
# user-visible filename and have caused trouble in log scrapers, shells,
# and downstream consumers.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

# Maximum sane values (server-operational; wire-format limit is the
# distinct constant MAX_CHUNKS in shared.models). MAX_CHUNKS_PER_FILE is
# imported above and used by its real name.
_MAX_FILENAME_LEN = 255
# Largest valid visibility value, derived from the Visibility enum rather
# than a bare ``2`` so the bound tracks the enum if a level is ever added.
_MAX_VISIBILITY = int(Visibility.PUBLIC)

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

    Thin wrapper over the shared ``canonicalize_file_id`` (Phase 3B dedup);
    keeps the ``label``-bearing message so callers' error logs are unchanged.
    """
    try:
        return canonicalize_file_id(value)
    except ValueError as exc:
        raise ValueError(f"Invalid {label} format") from exc


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

    # STG-5: reclaim this user's just-expired, non-finalizing staging rows
    # (and their dirs) synchronously before evaluating caps, so expired-but-
    # uncollected bytes/sessions don't sit cap-invisible until the periodic
    # GC. The window where they are unaccounted is now bounded by a single
    # request rather than the GC interval.
    reclaimed = await asyncio.to_thread(
        state.db.reclaim_expired_staging_for_user, identity.user_id
    )
    if reclaimed:
        await asyncio.to_thread(_remove_staging_dirs, state.staging_dir, reclaimed)

    # Generate upload ID (server-generated, always safe). It MUST be in the
    # same canonical 32-char no-hyphen form _validate_id returns, so the
    # staging dir, the DB row, and the later chunk/finalize lookups (which
    # run upload_id through _validate_id, stripping hyphens) all agree on
    # the same key. A hyphenated str(uuid4()) would never match the
    # canonicalized lookup, so every chunk POST would 400.
    upload_id = uuid.uuid4().hex
    staging_path = _safe_path(state.staging_dir, upload_id)

    # K3 / STG-4: count open uploads + insert the row in ONE transaction so
    # two concurrent inits at the cap cannot both pass a snapshot count and
    # both insert past MAX_OPEN_UPLOADS_PER_USER.
    #
    # The insert happens BEFORE makedirs so the orphan-dir scanner's
    # "canonical-id dir with no row => orphan" invariant always holds for a
    # live upload — closing the makedirs->insert race where the background
    # scanner could rmtree a live staging dir. If makedirs then fails we drop
    # the row; a crash in between leaves a harmless row-without-dir that the
    # expired-staging-row sweep reclaims at expiry.
    inserted = await asyncio.to_thread(
        state.db.try_create_staging_upload,
        upload_id=upload_id,
        owner_id=identity.user_id,
        filename=filename,
        expected_chunks=expected_chunks,
        expiry_seconds=state.staging_expiry,
        max_open_uploads=MAX_OPEN_UPLOADS_PER_USER,
    )
    if not inserted:
        return jsonify({"error": "Too many open uploads"}), 429

    try:
        await asyncio.to_thread(os.makedirs, staging_path, mode=0o700, exist_ok=True)
    except Exception:
        try:
            await asyncio.to_thread(state.db.delete_staging_upload, upload_id)
        except Exception:
            logger.warning(
                "Failed to delete staging row after makedirs error: %s", upload_id
            )
        raise

    return jsonify({"upload_id": upload_id}), 201


async def _persist_staged_chunk(
    state: AppState,
    *,
    upload_id: str,
    chunk_index: int,
    owner_id: str,
    chunk_data: bytes,
):
    """Write a validated chunk to staging, gated transactionally on quota.

    Write-temp-then-promote (STG-1 / STG-3 / PERF-2):

    * Phase 1 writes the bytes to a TEMP file in the upload's staging dir,
      OUTSIDE the DB lock and WITHOUT fsync — so concurrent uploads don't
      serialize on disk I/O and a chunk that is about to be rejected costs no
      durable write.
    * Phase 2 does a transactional check-and-insert. The quota/staging
      comparison charges only the size DELTA for a re-uploaded index
      (subtracting the existing row's chunk_size, STG-3) so an idempotent
      re-upload is not double-counted. Gating the check inside the same
      transaction as the insert is what stops two parallel uploads from one
      user both passing a snapshot check and overshooting (Round-2 H2/H3).
    * Phase 3 promotes the temp to its final ``{idx}.bin`` (fsync + atomic
      replace) ONLY on success. A rejected chunk drops the temp and NEVER
      touches an already-accepted chunk at this index — the previous code
      ``os.replace``d into the final path BEFORE the quota txn and then
      unconditionally unlinked it on rejection, destroying a re-uploaded
      chunk while its ``staging_chunks`` row survived, so finalize later
      promoted a blob missing a chunk.

    Returns the final response tuple (200 with the chunk hash, or 413/500).
    """
    new_chunk_size = len(chunk_data)
    chunk_hash = blake2b_hash(chunk_data).hex()
    staging_upload_dir = _safe_path(state.staging_dir, upload_id)
    final_path = _safe_path(state.staging_dir, upload_id, f"{chunk_index}.bin")

    try:
        tmp_path = await asyncio.to_thread(
            _write_temp_chunk, staging_upload_dir, chunk_data
        )
    except OSError as exc:
        logger.warning(
            "chunk temp write failed for upload_id=%s idx=%d: %s",
            upload_id,
            chunk_index,
            exc,
        )
        return jsonify({"error": "Upload failed"}), 500

    def _check_and_insert() -> tuple[bool, str]:
        with state.db.transaction():
            used, quota = state.db.get_user_usage(owner_id)
            staging = state.db.get_total_staging_bytes(owner_id)
            # STG-3: `staging` already includes any prior row for this exact
            # index, so charge only the size delta on a re-upload.
            existing = state.db.get_staging_chunk_size(upload_id, chunk_index)
            delta = new_chunk_size - (existing or 0)
            if used + staging + delta > quota:
                return False, "Quota exceeded"
            if staging + delta > MAX_STAGING_BYTES_PER_USER:
                return False, "Staging quota exceeded"
            state.db.add_staging_chunk(
                upload_id=upload_id,
                chunk_index=chunk_index,
                chunk_hash=chunk_hash,
                chunk_size=new_chunk_size,
            )
            return True, ""

    promoted = False
    try:
        ok, err_msg = await asyncio.to_thread(_check_and_insert)
        if not ok:
            return jsonify({"error": err_msg}), 413
        try:
            await asyncio.to_thread(_promote_temp_chunk, tmp_path, final_path)
        except OSError as exc:
            logger.warning(
                "chunk promote failed for upload_id=%s idx=%d: %s",
                upload_id,
                chunk_index,
                exc,
            )
            return jsonify({"error": "Upload failed"}), 500
        promoted = True
        return jsonify({"chunk_hash": chunk_hash}), 200
    finally:
        # On any non-success path (rejection, promote failure, or an
        # unexpected error from the txn) drop the temp; on success
        # os.replace already consumed it. Only the temp WE created here is
        # ever removed — never the established {idx}.bin.
        if not promoted:
            with contextlib.suppress(OSError):
                await asyncio.to_thread(os.unlink, tmp_path)


@storage_bp.route("/upload/<upload_id>/chunk/<int:chunk_index>", methods=["POST"])
@require_auth
async def upload_chunk(upload_id: str, chunk_index: int):
    """Upload a single encrypted chunk.

    Request body: raw ciphertext bytes (Content-Type: application/octet-stream)
    Response: {"chunk_hash": str}
    """
    state = app_state()
    identity = current_identity()

    try:
        upload_id = _validate_id(upload_id, "upload_id")
    except ValueError:
        return jsonify({"error": "Invalid request"}), 400

    # Enforce content-type (#11).
    content_type = request.content_type or ""
    if not content_type.startswith("application/octet-stream"):
        return jsonify({"error": "Invalid content type"}), 415

    # Validate chunk_index range (#17).
    if chunk_index < 0 or chunk_index >= MAX_CHUNKS_PER_FILE:
        return jsonify({"error": "Invalid request"}), 400

    upload = await asyncio.to_thread(state.db.get_staging_upload, upload_id)
    if upload is None or upload["owner_id"] != identity.user_id:
        return jsonify({"error": "Invalid request"}), 400

    # Refuse new chunks once finalize has claimed this upload (#H19).
    # Without this, a slow chunk write could rename into the just-
    # renamed-away staging dir under the wrong path, or — worse — land
    # inside `<blob_dir>/<file_id>/N.bin` and clobber a legitimate chunk
    # in the finalized file. (Round-3 H3)
    if upload.get("finalizing", 0):
        return jsonify({"error": "Upload finalizing"}), 410

    # Reject chunk_index >= expected_chunks so an attacker can't write
    # 100k tiny chunks to arbitrary indices for a 3-chunk upload
    # (inode-exhaustion + per-row DB cost). (Round-3 M6)
    expected_chunks = upload.get("expected_chunks")
    if expected_chunks is not None and chunk_index >= expected_chunks:
        return jsonify({"error": "Invalid request"}), 400

    # #5: Enforce upload expiry at request time.
    if time.time() > upload["expires_at"]:
        return jsonify({"error": "Upload expired"}), 410

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

    # Minimum chunk size for all but the last chunk. The last chunk's size
    # is determined by file length so it may be smaller.
    if (
        expected_chunks is not None
        and chunk_index < expected_chunks - 1
        and len(chunk_data) < MIN_CHUNK_SIZE
    ):
        return jsonify({"error": "Chunk too small"}), 400

    return await _persist_staged_chunk(
        state,
        upload_id=upload_id,
        chunk_index=chunk_index,
        owner_id=identity.user_id,
        chunk_data=chunk_data,
    )


@dataclass(frozen=True)
class _FinalizeRequest:
    """Validated finalize-request fields (server-trusted after parsing).

    ``expected_hashes`` is the RAW value from the body (possibly ``None`` or
    a non-list): its presence/type/length are checked post-claim inside
    ``_verify_staged_chunks`` so a malformed list still triggers the same
    ``_cleanup_staging`` path the original handler used (preserving DB state
    on that branch).
    """

    file_id: str
    total_chunks: int
    visibility: int
    file_header: bytes
    encrypted_metadata: bytes
    expected_hashes: object


def _validate_finalize_request(
    data: dict, expected_chunks: int | None
) -> _FinalizeRequest | None:
    """Strictly parse + range-check the finalize JSON body.

    Returns the validated request, or ``None`` if any field is missing,
    mistyped, or out of range — the caller maps ``None`` to a uniform 400.
    Pure (no I/O, no staging cleanup): cleanup only applies AFTER the
    finalizing claim, so this stays side-effect free.

    Strict ``isinstance`` checks (rejecting bool-as-int, int-as-str, etc.)
    are preserved from the original handler. (Round-3 H4 / H5)
    """
    raw_file_id = data.get("file_id")
    if not isinstance(raw_file_id, str):
        return None
    try:
        file_id = _validate_id(raw_file_id, "file_id")
    except ValueError:
        return None

    raw_total_chunks = data.get("total_chunks")
    if not isinstance(raw_total_chunks, int) or isinstance(raw_total_chunks, bool):
        return None
    total_chunks = raw_total_chunks
    if total_chunks < 1 or total_chunks > MAX_CHUNKS_PER_FILE:
        return None

    raw_visibility = data.get("visibility", int(Visibility.PRIVATE))
    if not isinstance(raw_visibility, int) or isinstance(raw_visibility, bool):
        return None
    visibility = raw_visibility
    if visibility < int(Visibility.PRIVATE) or visibility > _MAX_VISIBILITY:
        return None

    try:
        file_header = bytes.fromhex(data.get("file_header", ""))
        encrypted_metadata = bytes.fromhex(data.get("encrypted_metadata", ""))
    except (ValueError, TypeError):
        return None
    if not file_header or not encrypted_metadata:
        return None

    # Per-field size caps. MAX_CONTENT_LENGTH (5 MiB) bounds the whole
    # request, but without per-field caps an attacker could store a
    # 2.5 MiB file_header + 2.5 MiB encrypted_metadata BLOB in the DB.
    # The wire-format contract is MAX_HEADER_BYTES=4096 and
    # MAX_METADATA_BYTES=65536. (Round-4 H1)
    if len(file_header) > MAX_HEADER_BYTES:
        return None
    if len(encrypted_metadata) > MAX_METADATA_BYTES:
        return None

    if expected_chunks is not None and total_chunks != expected_chunks:
        return None

    # expected_hashes is intentionally NOT validated here — it is checked
    # post-claim in _verify_staged_chunks so its failure path runs the same
    # _cleanup_staging the original handler did.
    return _FinalizeRequest(
        file_id=file_id,
        total_chunks=total_chunks,
        visibility=visibility,
        file_header=file_header,
        encrypted_metadata=encrypted_metadata,
        expected_hashes=data.get("expected_hashes"),
    )


def _verify_staged_chunks(staged_chunks: list, req: _FinalizeRequest) -> bool:
    """Verify staged chunks match the finalize request, in the exact order.

    Checks, in the SAME order as the original handler: chunk count,
    contiguous indices 0..N-1, ``expected_hashes`` present + a list of the
    right length, then a per-chunk constant-time hash compare. Returns
    ``True`` iff every gate passes; the caller is responsible for
    ``_cleanup_staging`` + 400 on ``False`` (no cleanup here, so the side
    effect stays at the single call site).

    The per-chunk compare uses ``hmac.compare_digest``: the hashes are
    public to both ends so a naive ``!=`` is not catastrophic, but
    compare_digest closes a latent timing channel that could probe a
    known-plaintext exfiltration in a hostile-client scenario.
    """
    if len(staged_chunks) != req.total_chunks:
        return False
    chunk_indices = {c["chunk_index"] for c in staged_chunks}
    if chunk_indices != set(range(req.total_chunks)):
        return False

    expected_hashes = req.expected_hashes
    if not expected_hashes or not isinstance(expected_hashes, list):
        return False
    if len(expected_hashes) != req.total_chunks:
        return False

    for chunk, expected in zip(staged_chunks, expected_hashes, strict=True):
        if not isinstance(expected, str) or len(expected) != len(chunk["chunk_hash"]):
            return False
        if not hmac.compare_digest(chunk["chunk_hash"], expected):
            return False
    return True


def _staged_chunk_files_present(
    staging_dir: str, upload_id: str, total_chunks: int
) -> bool:
    """Confirm every expected ``{idx}.bin`` actually exists on disk.

    ``_verify_staged_chunks`` inspects only DB rows + hashes, and a chunk's
    ``staging_chunks`` row is committed BEFORE its ``{idx}.bin`` is durably
    promoted (the promote runs after the quota txn commits). A promote that
    fails therefore leaves a committed row with no file on disk. Because
    finalize promotes the whole staging dir into the blob dir with a single
    ``os.rename``, that gap would publish a blob missing a chunk. This guard
    stats each expected file (O(total_chunks)) so the caller can fail finalize
    before the rename. Offloaded via ``asyncio.to_thread`` like the other FS
    ops.
    """
    for idx in range(total_chunks):
        if not os.path.isfile(_safe_path(staging_dir, upload_id, f"{idx}.bin")):
            return False
    return True


def _commit_finalized_blob(
    state: AppState,
    *,
    upload_id: str,
    owner_id: str,
    filename: str,
    req: _FinalizeRequest,
    total_bytes: int,
) -> None:
    """Atomically promote staging→blob and commit the DB row (one txn).

    Phase 1 is a single atomic directory rename (``os.rename`` refuses to
    clobber a non-empty destination, so a file_id collision fails before
    touching the existing blob). Phase 2 does create_file + commit_usage +
    the staging-row delete in ONE transaction so a crash anywhere between
    them leaves the DB consistent (Round-3 H2). On any DB failure the
    rename is rolled back; a failed rollback is logged as an orphan blob.

    Raises:
        QuotaExceededError: caller maps to 413.
        StorageError: file_id collision; caller maps to 409.
        Exception: any other failure; caller maps to 500.
    """
    blob_path = _safe_path(state.blob_dir, req.file_id)
    src_dir = _safe_path(state.staging_dir, upload_id)

    # Phase 1: atomic directory rename.
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

    # Phase 2: DB commit.
    try:
        with state.db.transaction() as _conn:
            check_quota(state.db, owner_id, total_bytes)
            state.db.create_file(
                file_id=req.file_id,
                owner_id=owner_id,
                filename=filename,
                visibility=req.visibility,
                total_chunks=req.total_chunks,
                total_bytes=total_bytes,
                encrypted_metadata=req.encrypted_metadata,
                file_header=req.file_header,
            )
            commit_usage(state.db, owner_id, total_bytes)
            _conn.execute(
                "DELETE FROM staging_uploads WHERE upload_id = ?",
                (upload_id,),
            )
    except Exception:
        # Undo the rename: move blob_path back. If THIS fails we have a
        # real orphan — log it loudly.
        try:
            os.rename(blob_path, src_dir)
        except OSError:
            logger.error(
                "ORPHAN BLOB: rolled-back finalize left "
                "blob_path=%s with no DB record",
                blob_path,
            )
        raise


async def _claim_finalizing(state: AppState, upload_id: str) -> bool | None:
    """Atomically claim the staging row for finalize (wire H19 protection).

    Until this transaction commits, the background cleanup task cannot
    delete the staging row out from under us. The ``finalizing = 1`` flag
    remains set if a later step fails; ``_cleanup_staging`` deletes by
    upload_id regardless of the flag so a failed finalize still releases
    the row.

    Returns the claim outcome (``True`` claimed / ``False`` lost the race),
    or ``None`` if the claim transaction itself errored (caller maps to 500).
    """

    def _claim() -> bool:
        with state.db.transaction():
            return state.db.mark_upload_finalizing(upload_id)

    try:
        return await asyncio.to_thread(_claim)
    except Exception:
        logger.exception("Failed to claim staging upload for finalize")
        return None


async def _run_finalize_commit(
    state: AppState,
    *,
    upload_id: str,
    owner_id: str,
    filename: str,
    req: _FinalizeRequest,
    total_bytes: int,
):
    """Run the commit in a worker thread and map outcomes to a response.

    Returns the success ``{"file_id": ...}`` 201 tuple, or the mapped error
    tuple (413 quota / 409 collision / 500 unexpected).

    STG-2: a successful commit deletes the staging row, but every FAILURE
    branch here leaves the row intact with ``finalizing = 1`` (set by the
    earlier claim). Without clearing it, a retry would hit
    ``mark_upload_finalizing`` -> False -> a misleading "Upload expired" 410,
    and the bytes stay cap-invisible until the expiry+grace sweep. So each
    failure branch clears the claim (``clear_finalizing``) so the client can
    retry and the cleanup path sees an un-claimed row again. The returned
    status still conveys the real cause (413 quota / 409 collision / 500
    transient) — never a false expiry.
    """
    try:
        await asyncio.to_thread(
            _commit_finalized_blob,
            state,
            upload_id=upload_id,
            owner_id=owner_id,
            filename=filename,
            req=req,
            total_bytes=total_bytes,
        )
    except QuotaExceededError:
        await asyncio.to_thread(state.db.clear_finalizing, upload_id)
        return jsonify({"error": "Quota exceeded"}), 413
    except StorageError as exc:
        # Known collision — surfaced as 409.
        logger.info("Finalize rejected: %s (upload_id=%s)", exc, upload_id)
        await asyncio.to_thread(state.db.clear_finalizing, upload_id)
        return jsonify({"error": "Invalid request"}), 409
    except Exception:
        logger.exception(
            "Finalize failed for upload_id=%s file_id=%s", upload_id, req.file_id
        )
        await asyncio.to_thread(state.db.clear_finalizing, upload_id)
        return jsonify({"error": "Upload failed"}), 500
    return jsonify({"file_id": req.file_id}), 201


@storage_bp.route("/upload/<upload_id>/finalize", methods=["POST"])
@require_auth
async def upload_finalize(upload_id: str):
    """Finalize an upload: verify integrity, check quota, commit.

    Request: {file_id, total_chunks, file_header (hex),
    encrypted_metadata (hex), visibility, expected_hashes: [str]}.
    Response: {"file_id": str} on success.
    """
    state = app_state()
    identity = current_identity()

    try:
        upload_id = _validate_id(upload_id, "upload_id")
    except ValueError:
        return jsonify({"error": "Invalid request"}), 400

    data = await request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    upload = await asyncio.to_thread(state.db.get_staging_upload, upload_id)
    if upload is None or upload["owner_id"] != identity.user_id:
        return jsonify({"error": "Invalid request"}), 400

    # #5: Enforce upload expiry at request time.
    if time.time() > upload["expires_at"]:
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Upload expired"}), 410

    req = _validate_finalize_request(data, upload["expected_chunks"])
    if req is None:
        return jsonify({"error": "Invalid request"}), 400

    claimed = await _claim_finalizing(state, upload_id)
    if claimed is None:
        return jsonify({"error": "Upload failed"}), 500
    if not claimed:
        # Already finalizing in another request, or row was deleted by an
        # earlier expiry sweep that won the race.
        return jsonify({"error": "Upload expired"}), 410

    staged_chunks = await asyncio.to_thread(state.db.get_staging_chunks, upload_id)
    if not _verify_staged_chunks(staged_chunks, req):
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Invalid request"}), 400

    # The DB-only check above can pass while a chunk's {idx}.bin is absent: the
    # staging_chunks row commits before the promote, so a failed promote leaves
    # a committed row with no file. The finalize dir-rename would then publish a
    # blob missing a chunk. Confirm every expected file is on disk first; if any
    # is missing, discard the staging dir and reject so the client re-uploads.
    if not await asyncio.to_thread(
        _staged_chunk_files_present, state.staging_dir, upload_id, req.total_chunks
    ):
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Invalid request"}), 409

    total_bytes = sum(c["chunk_size"] for c in staged_chunks)
    total_bytes += len(req.encrypted_metadata) + len(req.file_header)

    return await _run_finalize_commit(
        state,
        upload_id=upload_id,
        owner_id=identity.user_id,
        filename=upload["filename"],
        req=req,
        total_bytes=total_bytes,
    )


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


def _timing_dummy_write(conn: sqlite3.Connection, file_id: str, user_id: str) -> None:
    """Idempotent no-op write matching the real share/unshare tx shape.

    The "no real recipient" branch of the timing-equalized share/unshare
    endpoints must still take Database._lock + the SQLite reserved lock and
    commit a WAL frame, so its latency matches the real branch. ``SET col =
    col`` is NOT short-circuited by SQLite (verified empirically — it still
    emits a WAL frame), so these two updates against the same hot rows give
    the dummy path the same lock + fsync cost. The constant-deadline sleep
    at the call site caps the remaining sub-millisecond variance. (Round-7
    H1/H2)
    """
    conn.execute("UPDATE files SET file_id = file_id WHERE file_id = ?", (file_id,))
    conn.execute("UPDATE users SET user_id = user_id WHERE user_id = ?", (user_id,))


def _apply_share(
    state: AppState,
    *,
    file_id: str,
    caller_id: str,
    target_user: dict | None,
    wrapped_keys: bytes,
) -> None:
    """Add the share row (or run equivalent dummy work) in ONE write tx.

    Three mutually-exclusive cases, all entering an identical-shape write
    transaction so the timing-equalized endpoint cannot leak which one ran:

    * Real share (an existing OTHER user): insert the wrapped-keys row and
      promote PRIVATE→SHARED.
    * Self-share (target IS the caller) — an EXPLICIT success no-op: the
      owner already has access, so we never write a self share-row here
      (the dedicated POST /self_keys path owns owner bundles). We still run
      the dummy write so a self-share is timing-indistinguishable from an
      unknown target. (SEC-L1)
    * Unknown / non-canonicalizable target (``target_user is None``): dummy
      write only.

    Both blank branches contend on Database._lock + the SQLite reserved
    lock and commit a WAL frame identically to the real branch.
    """
    # Real share only for an existing user that is NOT the caller; a
    # self-share falls through to the dummy write (explicit no-op).
    real_target = (
        target_user
        if target_user is not None and target_user["user_id"] != caller_id
        else None
    )

    with state.db.transaction() as conn:
        if real_target is not None:
            state.db.add_file_share(
                file_id=file_id,
                shared_with_id=real_target["user_id"],
                wrapped_keys=wrapped_keys,
            )
            # Promote PRIVATE -> SHARED; MAX keeps PUBLIC unchanged.
            conn.execute(
                "UPDATE files SET visibility = MAX(visibility, ?) "
                "WHERE file_id = ? AND visibility = ?",
                (int(Visibility.SHARED), file_id, int(Visibility.PRIVATE)),
            )
        else:
            # Self-share no-op OR unknown target: equivalent dummy write.
            _timing_dummy_write(conn, file_id, caller_id)


def _apply_unshare(
    state: AppState,
    *,
    file_id: str,
    caller_id: str,
    target_user: dict | None,
) -> None:
    """Remove a share row (or run equivalent dummy work) in ONE write tx.

    Real branch (existing target user): delete the wrapped-keys row and, if
    no shares remain and the file isn't PUBLIC, downgrade SHARED→PRIVATE so
    the server access policy matches the absence of share rows. Unknown /
    non-canonicalizable target: an equivalent dummy write that contends on
    the same locks and commits a WAL frame, so timing does not leak
    existence. (Round-7 H1/H2)
    """
    with state.db.transaction() as conn:
        if target_user is not None:
            state.db.remove_file_share(
                file_id=file_id,
                shared_with_id=target_user["user_id"],
            )
            remaining_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM file_shares WHERE file_id = ?",
                (file_id,),
            ).fetchone()
            if remaining_row and remaining_row["cnt"] == 0:
                # Downgrade SHARED -> PRIVATE only (PUBLIC is left as-is).
                conn.execute(
                    "UPDATE files SET visibility = ? "
                    "WHERE file_id = ? AND visibility = ?",
                    (int(Visibility.PRIVATE), file_id, int(Visibility.SHARED)),
                )
        else:
            _timing_dummy_write(conn, file_id, caller_id)


def _parse_share_body(data) -> tuple[str | None, bytes] | None:
    """Validate the /share JSON body; return (canonical_target, wrapped_keys).

    Returns ``None`` for a structurally invalid body (caller maps to 400).
    The canonical target is ``None`` when the username fails to canonicalize
    — a VALID body whose target simply doesn't resolve, which the caller
    routes through the uniform timing-equalized dummy path (no 400, no
    enumeration). Canonicalizing here lets a share aimed at "Alice" or
    fullwidth "ＡＬＩＣＥ" land on the canonical "alice" row. (Round-4 H2)
    """
    if not data or "shared_with" not in data or "wrapped_keys" not in data:
        return None
    raw_target = data["shared_with"]
    if not isinstance(raw_target, str):
        return None
    if not raw_target or len(raw_target) > MAX_USERNAME_LEN:
        return None
    try:
        target_username: str | None = _canonicalize_username(raw_target)
    except AuthError:
        target_username = None

    try:
        wrapped_keys = bytes.fromhex(data["wrapped_keys"])
    except (ValueError, TypeError):
        return None
    if not (MIN_WRAPPED_KEYS_BYTES <= len(wrapped_keys) <= MAX_WRAPPED_KEYS_BYTES):
        return None
    return target_username, wrapped_keys


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

    parsed = _parse_share_body(await request.get_json(silent=True))
    if parsed is None:
        return jsonify({"error": "Invalid request"}), 400
    target_username, wrapped_keys = parsed

    # Start the timing budget BEFORE the username lookup so its latency is
    # also inside the constant-deadline envelope. The user-row fetch touches
    # BLOB columns (ed25519_pubkey, password_hash) for existing users vs an
    # empty index probe for unknown users — otherwise that delta leaks
    # outside the budget. (Round-7 M3)
    started = time.monotonic()

    # Look up target — if missing, _apply_share runs an EQUIVALENT amount of
    # DB work in the same shape so an attacker can't enumerate via lock
    # contention or fsync tail. (Round-7 H1/H2)
    target_user = (
        await asyncio.to_thread(state.db.get_user_by_username, target_username)
        if target_username is not None
        else None
    )

    await asyncio.to_thread(
        _apply_share,
        state,
        file_id=file_id,
        caller_id=identity.user_id,
        target_user=target_user,
        wrapped_keys=wrapped_keys,
    )
    # Constant-deadline sleep: the combination of (a) identical
    # write-transaction shape between branches and (b) this constant cap is
    # what closes the timing oracle even under WAL fsync tail or lock
    # contention. (Round-7 H1)
    await sleep_until_deadline(started)
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
    except AuthError:
        canon_recipient = None

    # Start the timing budget BEFORE the username lookup so its latency is
    # inside the constant-deadline envelope. (Round-7 M3)
    started = time.monotonic()

    target_user = (
        await asyncio.to_thread(state.db.get_user_by_username, canon_recipient)
        if canon_recipient is not None
        else None
    )

    await asyncio.to_thread(
        _apply_unshare,
        state,
        file_id=file_id,
        caller_id=identity.user_id,
        target_user=target_user,
    )
    await sleep_until_deadline(started)
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


def _write_temp_chunk(directory: str, data: bytes) -> str:
    """Write ``data`` to a fresh temp file in ``directory`` WITHOUT fsync.

    Returns the temp path. The caller promotes it to its final ``{idx}.bin``
    name with ``_promote_temp_chunk`` ONLY after the quota/staging
    transaction accepts the chunk (STG-1), so a rejected over-quota chunk
    never overwrites an already-accepted chunk at the same index and never
    costs a durable write (PERF-2: fsync is paid only on a successful
    promote). mkstemp creates the file 0o600.

    On ANY failure of ``os.write`` (or ``os.close``) the temp file is
    unlinked before the exception propagates — mirrors ``_write_file_bytes``.
    Otherwise a leaked ``.chunk-*.tmp`` would survive in the staging dir and
    the finalize dir-rename (whole-dir ``os.rename`` staging->blob) would
    publish it into the blob dir.
    """
    fd: int | None = None
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".chunk-", suffix=".tmp")
        os.write(fd, data)
        os.close(fd)
        fd = None
        result = tmp_path
        tmp_path = None  # success: caller owns the temp; don't unlink it below
        return result
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        if tmp_path is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)


def _promote_temp_chunk(tmp_path: str, final_path: str) -> None:
    """Durably promote an accepted temp chunk to its final path.

    fsyncs the temp file's bytes (PERF-2: durability is paid only for an
    accepted chunk), then atomically ``os.replace``s it into place — a
    concurrent reader/finalize sees either the prior chunk or the fully
    written new one, never a torn file. ``os.replace`` consumes the temp on
    success; on failure it leaves both the temp and the established
    ``final_path`` untouched (the caller removes the temp).
    """
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp_path, final_path)


def _remove_staging_dirs(staging_dir: str, upload_ids: list[str]) -> None:
    """Best-effort rmtree of synchronously-reclaimed staging dirs (STG-5).

    The DB rows are already gone (``reclaim_expired_staging_for_user``
    deleted them atomically), so a directory that fails to remove here is at
    worst reclaimed later by the orphan scanner. FS errors are logged and
    swallowed.
    """
    for upload_id in upload_ids:
        try:
            path = _safe_path(staging_dir, upload_id)
        except ValueError:
            continue
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
        except OSError as exc:
            logger.warning(
                "STG-5 reclaim: failed to remove staging dir %s: %s",
                upload_id,
                exc,
            )


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
    no corresponding row in ``staging_uploads``. ``upload_init`` now inserts
    the DB row BEFORE ``os.makedirs`` (race fix), so a live upload always has
    a row before its dir exists — this no longer races a live upload and
    remains a backstop for foreign/leftover directories.

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
        if not is_canonical_id(name):
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
