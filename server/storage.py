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
import logging
import os
import re
import shutil
import time
import uuid
from typing import Optional

from quart import Blueprint, jsonify, request, send_file

from server.auth import require_auth
from server.database import Database
from server.policy import check_file_access, check_file_ownership
from server.quota import check_quota, commit_usage, release_usage
from shared.crypto import blake2b_hash
from shared.exceptions import (
    AuthError,
    QuotaExceededError,
    StorageError,
    UploadError,
)

logger = logging.getLogger("localcloud.storage")

# ──────────────────────────── Constants ────────────────────────────

# Strict pattern for file_id and upload_id: lowercase hex UUID (no hyphens) or UUID4
_SAFE_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SAFE_HEX_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# Maximum sane values
_MAX_CHUNKS = 100_000  # Max ~400 GiB per file at 4 MiB chunks
_MAX_FILENAME_LEN = 255
_MAX_VISIBILITY = 2

# ──────────────────────────── Blueprint ────────────────────────────

storage_bp = Blueprint("storage", __name__, url_prefix="/api/files")

_db: Optional[Database] = None
_blob_dir: str = ""
_staging_dir: str = ""
_staging_expiry: int = 3600
_max_chunk_size: int = 5 * 1024 * 1024  # 5 MiB (chunk + overhead)


def init_storage(
    db: Database,
    blob_dir: str,
    staging_dir: str,
    staging_expiry: int = 3600,
) -> None:
    """Initialize storage module with dependencies."""
    global _db, _blob_dir, _staging_dir, _staging_expiry
    _db = db
    _blob_dir = os.path.realpath(blob_dir)
    _staging_dir = os.path.realpath(staging_dir)
    _staging_expiry = staging_expiry


# ──────────────────────────── Validation Helpers ────────────────────────────


def _validate_id(value: str, label: str = "ID") -> str:
    """Validate that a value is a safe identifier (UUID4 or 32-char hex).

    Prevents path traversal by enforcing a strict allowlist format.
    """
    if _SAFE_ID_RE.match(value) or _SAFE_HEX_ID_RE.match(value):
        return value
    raise ValueError(f"Invalid {label} format")


def _safe_path(base_dir: str, *components: str) -> str:
    """Build a path and verify it stays within base_dir.

    Resolves symlinks and relative path tricks, then checks containment.
    """
    joined = os.path.join(base_dir, *components)
    canonical = os.path.realpath(joined)
    # Containment check: canonical path must start with base_dir + separator
    if not canonical.startswith(base_dir + os.sep) and canonical != base_dir:
        raise ValueError("Path traversal detected")
    return canonical


# ──────────────────────────── Upload API ────────────────────────────


@storage_bp.route("/upload/init", methods=["POST"])
@require_auth
async def upload_init():
    """Initialize a new upload session.

    Request: {"filename": str, "expected_chunks": int}
    Response: {"upload_id": str}
    """
    assert _db is not None

    data = await request.get_json(silent=True)
    if not data or "filename" not in data:
        return jsonify({"error": "Invalid request"}), 400

    filename = str(data["filename"])
    if not filename or len(filename) > _MAX_FILENAME_LEN:
        return jsonify({"error": "Invalid request"}), 400

    # Validate expected_chunks if provided
    expected_chunks = data.get("expected_chunks")
    if expected_chunks is not None:
        try:
            expected_chunks = int(expected_chunks)
            if expected_chunks < 1 or expected_chunks > _MAX_CHUNKS:
                return jsonify({"error": "Invalid request"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid request"}), 400

    # Generate upload ID (server-generated, always safe)
    upload_id = str(uuid.uuid4())
    staging_path = _safe_path(_staging_dir, upload_id)
    await asyncio.to_thread(os.makedirs, staging_path, 0o700, True)  # #16

    # Record in database
    await asyncio.to_thread(
        _db.create_staging_upload,
        upload_id=upload_id,
        owner_id=request.user_id,  # type: ignore
        filename=filename,
        expected_chunks=expected_chunks,
        expiry_seconds=_staging_expiry,
    )

    return jsonify({"upload_id": upload_id}), 201


@storage_bp.route("/upload/<upload_id>/chunk/<int:chunk_index>", methods=["POST"])
@require_auth
async def upload_chunk(upload_id: str, chunk_index: int):
    """Upload a single encrypted chunk.

    Request body: raw ciphertext bytes (Content-Type: application/octet-stream)
    Response: {"chunk_hash": str}
    """
    assert _db is not None

    # Validate IDs
    try:
        _validate_id(upload_id, "upload_id")
    except ValueError:
        return jsonify({"error": "Invalid request"}), 400

    # Enforce content-type (#11)
    content_type = request.content_type or ""
    if not content_type.startswith("application/octet-stream"):
        return jsonify({"error": "Invalid content type"}), 415

    # Validate chunk_index range (#17)
    if chunk_index < 0 or chunk_index >= _MAX_CHUNKS:
        return jsonify({"error": "Invalid request"}), 400

    # Verify upload exists and belongs to this user
    upload = await asyncio.to_thread(_db.get_staging_upload, upload_id)
    if upload is None or upload["owner_id"] != request.user_id:  # type: ignore
        return jsonify({"error": "Invalid request"}), 400

    # #5: Enforce upload expiry at request time
    if time.time() > upload["expires_at"]:
        return jsonify({"error": "Upload expired"}), 410

    # Read chunk data
    chunk_data = await request.get_data(as_text=False)
    if not chunk_data:
        return jsonify({"error": "Empty chunk"}), 400

    if len(chunk_data) > _max_chunk_size:
        return jsonify({"error": "Chunk too large"}), 413

    # Compute BLAKE2b hash of ciphertext
    chunk_hash = blake2b_hash(chunk_data).hex()

    # Write chunk to staging directory (path validated)
    chunk_path = _safe_path(_staging_dir, upload_id, f"{chunk_index}.bin")
    await asyncio.to_thread(_write_file_bytes, chunk_path, chunk_data)

    # Record chunk in database
    await asyncio.to_thread(
        _db.add_staging_chunk,
        upload_id=upload_id,
        chunk_index=chunk_index,
        chunk_hash=chunk_hash,
        chunk_size=len(chunk_data),
    )

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
    assert _db is not None

    # Validate upload_id
    try:
        _validate_id(upload_id, "upload_id")
    except ValueError:
        return jsonify({"error": "Invalid request"}), 400

    data = await request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    # Verify upload exists and belongs to this user
    upload = await asyncio.to_thread(_db.get_staging_upload, upload_id)
    if upload is None or upload["owner_id"] != request.user_id:  # type: ignore
        return jsonify({"error": "Invalid request"}), 400

    # #5: Enforce upload expiry at request time
    if time.time() > upload["expires_at"]:
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Upload expired"}), 410

    # Validate and sanitize file_id — CRITICAL for path traversal (#1)
    file_id = str(data.get("file_id", ""))
    try:
        _validate_id(file_id, "file_id")
    except ValueError:
        # #8: Recoverable — don't destroy staging for format errors
        return jsonify({"error": "Invalid request"}), 400

    # Validate total_chunks
    try:
        total_chunks = int(data.get("total_chunks", 0))
        if total_chunks < 1 or total_chunks > _MAX_CHUNKS:
            raise ValueError()
    except (ValueError, TypeError):
        # #8: Recoverable format error
        return jsonify({"error": "Invalid request"}), 400

    # #4: Guard visibility parsing with try/except
    try:
        visibility = int(data.get("visibility", 0))
    except (ValueError, TypeError):
        # #8: Recoverable format error
        return jsonify({"error": "Invalid request"}), 400

    if visibility < 0 or visibility > _MAX_VISIBILITY:
        return jsonify({"error": "Invalid request"}), 400

    try:
        file_header = bytes.fromhex(data.get("file_header", ""))
        encrypted_metadata = bytes.fromhex(data.get("encrypted_metadata", ""))
    except (ValueError, TypeError):
        # #8: Recoverable format error
        return jsonify({"error": "Invalid request"}), 400

    if not file_header or not encrypted_metadata:
        return jsonify({"error": "Invalid request"}), 400

    # #13: Enforce expected_chunks from upload init
    if upload["expected_chunks"] is not None:
        if total_chunks != upload["expected_chunks"]:
            # #8: Recoverable — client sent wrong count
            return jsonify({"error": "Invalid request"}), 400

    # Verify chunk count matches
    staged_chunks = await asyncio.to_thread(_db.get_staging_chunks, upload_id)
    if len(staged_chunks) != total_chunks:
        # Fatal: integrity violation — cleanup staging
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Invalid request"}), 400

    # Verify chunk indices are contiguous 0..total_chunks-1
    chunk_indices = {c["chunk_index"] for c in staged_chunks}
    if chunk_indices != set(range(total_chunks)):
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Invalid request"}), 400

    # Verify expected hashes — MANDATORY, strict length check (#3)
    expected_hashes = data.get("expected_hashes")
    if not expected_hashes or not isinstance(expected_hashes, list):
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Invalid request"}), 400

    if len(expected_hashes) != total_chunks:
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Invalid request"}), 400

    for chunk, expected in zip(staged_chunks, expected_hashes):
        if not isinstance(expected, str) or chunk["chunk_hash"] != expected:
            # Fatal: integrity violation — cleanup staging
            await asyncio.to_thread(_cleanup_staging, upload_id)
            return jsonify({"error": "Invalid request"}), 400

    # Check for file_id collision (#13) — fail if blob dir already exists
    blob_path = _safe_path(_blob_dir, file_id)
    if await asyncio.to_thread(os.path.exists, blob_path):  # #16
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Invalid request"}), 409

    # Calculate total ciphertext size
    total_bytes = sum(c["chunk_size"] for c in staged_chunks)
    total_bytes += len(encrypted_metadata) + len(file_header)

    # Two-phase commit (#8):
    # Phase 1: Stage filesystem (move chunks to blob dir)
    # Phase 2: Commit DB (quota + file record)
    # On failure: clean up filesystem, DB rolls back automatically
    try:
        # Phase 1: Filesystem staging
        await asyncio.to_thread(os.makedirs, blob_path, 0o700)  # #16

        try:
            for chunk in staged_chunks:
                src = _safe_path(_staging_dir, upload_id, f"{chunk['chunk_index']}.bin")
                dst = _safe_path(_blob_dir, file_id, f"{chunk['chunk_index']}.bin")
                await asyncio.to_thread(shutil.move, src, dst)
        except Exception:
            # Filesystem staging failed — clean up blob dir
            if await asyncio.to_thread(os.path.isdir, blob_path):  # #16
                await asyncio.to_thread(shutil.rmtree, blob_path)
            raise

        # Phase 2: DB commit (atomic via transaction)
        def _db_commit():
            with _db.transaction() as conn:
                check_quota(_db, request.user_id, total_bytes)  # type: ignore
                _db.create_file(
                    file_id=file_id,
                    owner_id=request.user_id,  # type: ignore
                    filename=upload["filename"],
                    visibility=visibility,
                    total_chunks=total_chunks,
                    total_bytes=total_bytes,
                    encrypted_metadata=encrypted_metadata,
                    file_header=file_header,
                )
                commit_usage(_db, request.user_id, total_bytes)  # type: ignore

        await asyncio.to_thread(_db_commit)

    except QuotaExceededError:
        # DB rolled back, clean up filesystem
        if await asyncio.to_thread(os.path.isdir, blob_path):  # #16
            await asyncio.to_thread(shutil.rmtree, blob_path)
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Quota exceeded"}), 413
    except Exception:
        # DB rolled back, clean up filesystem
        if await asyncio.to_thread(os.path.isdir, blob_path):  # #16
            await asyncio.to_thread(shutil.rmtree, blob_path)
        await asyncio.to_thread(_cleanup_staging, upload_id)
        return jsonify({"error": "Upload failed"}), 500

    # Clean up staging
    await asyncio.to_thread(_cleanup_staging, upload_id)

    return jsonify({"file_id": file_id}), 201


# ──────────────────────────── Download API ────────────────────────────


@storage_bp.route("/<file_id>", methods=["GET"])
@require_auth
async def get_file_metadata(file_id: str):
    """Get file metadata (header + encrypted metadata blob)."""
    assert _db is not None

    # Validate file_id format (#1)
    try:
        _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        file_record = await asyncio.to_thread(
            check_file_access, _db, file_id, request.user_id  # type: ignore
        )
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    return jsonify({
        "file_id": file_record["file_id"],
        "filename": file_record["filename"],
        "total_chunks": file_record["total_chunks"],
        "file_header": file_record["file_header"].hex()
            if isinstance(file_record["file_header"], bytes)
            else file_record["file_header"],
        "encrypted_metadata": file_record["encrypted_metadata"].hex()
            if isinstance(file_record["encrypted_metadata"], bytes)
            else file_record["encrypted_metadata"],
        "visibility": file_record["visibility"],
        "owner_id": file_record["owner_id"],  # #9: needed for sig verification
    }), 200


@storage_bp.route("/<file_id>/chunk/<int:chunk_index>", methods=["GET"])
@require_auth
async def get_chunk(file_id: str, chunk_index: int):
    """Download a single encrypted chunk (ciphertext only)."""
    assert _db is not None

    # Validate file_id format (#1)
    try:
        _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        file_record = await asyncio.to_thread(
            check_file_access, _db, file_id, request.user_id  # type: ignore
        )
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    if chunk_index < 0 or chunk_index >= file_record["total_chunks"]:
        return jsonify({"error": "Not found"}), 404

    # Build and validate path (#1)
    chunk_path = _safe_path(_blob_dir, file_id, f"{chunk_index}.bin")
    if not await asyncio.to_thread(os.path.isfile, chunk_path):  # #16
        return jsonify({"error": "Not found"}), 404

    return await send_file(
        chunk_path,
        mimetype="application/octet-stream",
    )


# ──────────────────────────── Delete ────────────────────────────


@storage_bp.route("/<file_id>", methods=["DELETE"])
@require_auth
async def delete_file(file_id: str):
    """Delete a file and release quota. Only the owner can delete.

    #7: DB-first ordering — delete metadata and release quota in a
    transaction first, then clean up filesystem. If FS cleanup fails,
    orphaned blobs are harmless (no metadata pointing to them).
    """
    assert _db is not None

    # Validate file_id format (#1)
    try:
        _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        file_record = await asyncio.to_thread(
            check_file_ownership, _db, file_id, request.user_id  # type: ignore
        )
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    total_bytes = file_record["total_bytes"]

    # #7: Phase 1: DB cleanup FIRST (atomic transaction)
    def _db_delete():
        with _db.transaction() as conn:
            _db.delete_file(file_id)
            release_usage(_db, request.user_id, total_bytes)  # type: ignore

    await asyncio.to_thread(_db_delete)

    # #7: Phase 2: Filesystem cleanup (best-effort after DB commit)
    blob_path = _safe_path(_blob_dir, file_id)
    try:
        if await asyncio.to_thread(os.path.isdir, blob_path):  # #16
            await asyncio.to_thread(shutil.rmtree, blob_path)
    except OSError:
        # Log but don't fail — orphaned blobs are harmless
        logger.warning("Failed to clean up blob dir: %s", file_id)

    return jsonify({"status": "deleted"}), 200


# ──────────────────────────── List Files ────────────────────────────


@storage_bp.route("", methods=["GET"])
@require_auth
async def list_files():
    """List all files accessible to the authenticated user."""
    assert _db is not None

    files = await asyncio.to_thread(
        _db.list_user_files, request.user_id  # type: ignore
    )
    result = []
    for f in files:
        result.append({
            "file_id": f["file_id"],
            "filename": f["filename"],
            "total_chunks": f["total_chunks"],
            "total_bytes": f["total_bytes"],
            "visibility": f["visibility"],
            "created_at": f["created_at"],
        })

    return jsonify({"files": result}), 200


# ──────────────────────────── Sharing ────────────────────────────


@storage_bp.route("/<file_id>/share", methods=["POST"])
@require_auth
async def share_file(file_id: str):
    """Share a file with another user by uploading wrapped keys."""
    assert _db is not None

    # Validate file_id (#1)
    try:
        _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        await asyncio.to_thread(
            check_file_ownership, _db, file_id, request.user_id  # type: ignore
        )
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    data = await request.get_json(silent=True)
    if not data or "shared_with" not in data or "wrapped_keys" not in data:
        return jsonify({"error": "Invalid request"}), 400

    target_user = await asyncio.to_thread(
        _db.get_user_by_username, str(data["shared_with"])
    )
    if target_user is None:
        return jsonify({"error": "Invalid request"}), 400

    try:
        wrapped_keys = bytes.fromhex(data["wrapped_keys"])
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid request"}), 400

    def _db_share():
        with _db.transaction() as conn:
            _db.add_file_share(
                file_id=file_id,
                shared_with_id=target_user["user_id"],
                wrapped_keys=wrapped_keys,
            )
            conn.execute(
                "UPDATE files SET visibility = MAX(visibility, 1) "
                "WHERE file_id = ? AND visibility = 0",
                (file_id,),
            )

    await asyncio.to_thread(_db_share)

    return jsonify({"status": "shared"}), 200


@storage_bp.route("/<file_id>/wrapped_keys", methods=["GET"])
@require_auth
async def get_wrapped_keys(file_id: str):
    """Get wrapped keys for the authenticated user."""
    assert _db is not None

    try:
        _validate_id(file_id, "file_id")
    except ValueError:
        return jsonify({"error": "Not found"}), 404

    try:
        await asyncio.to_thread(
            check_file_access, _db, file_id, request.user_id  # type: ignore
        )
    except AuthError:
        return jsonify({"error": "Not found"}), 404

    wrapped = await asyncio.to_thread(
        _db.get_wrapped_keys, file_id, request.user_id  # type: ignore
    )
    if wrapped is None:
        return jsonify({"wrapped_keys": None}), 200

    return jsonify({"wrapped_keys": wrapped.hex()}), 200


# ──────────────────────────── Quota ────────────────────────────


@storage_bp.route("/quota", methods=["GET"])
@require_auth
async def get_quota():
    """Get quota information for the authenticated user."""
    assert _db is not None
    from server.quota import get_quota_info
    info = await asyncio.to_thread(
        get_quota_info, _db, request.user_id  # type: ignore
    )
    return jsonify(info), 200


# ──────────────────────────── Internal Helpers ────────────────────────────


def _write_file_bytes(path: str, data: bytes) -> None:
    """Write bytes to a file atomically."""
    with open(path, "wb") as f:
        f.write(data)


def _cleanup_staging(upload_id: str) -> None:
    """Remove staging directory and database records for an upload."""
    assert _db is not None
    try:
        staging_path = _safe_path(_staging_dir, upload_id)
        if os.path.isdir(staging_path):
            shutil.rmtree(staging_path)
    except ValueError:
        pass  # Invalid ID — nothing to clean
    _db.delete_staging_upload(upload_id)


def cleanup_expired_uploads() -> int:
    """Garbage collect expired staging uploads. Returns count cleaned."""
    assert _db is not None
    expired = _db.cleanup_expired_staging()
    for upload_id in expired:
        try:
            staging_path = _safe_path(_staging_dir, upload_id)
            if os.path.isdir(staging_path):
                shutil.rmtree(staging_path)
        except ValueError:
            pass
    return len(expired)
