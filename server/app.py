from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import sys

from quart import Quart, jsonify, request

from server.auth import (
    assert_no_forwarded_header_middleware,
    assert_single_worker,
    auth_bp,
    init_auth,
    sweep_composite_attempts,
)
from server.config import ServerConfig
from server.database import Database
from server.state import AppState, store_app_state
from server.storage import (
    DEFAULT_MAX_CHUNK_SIZE,
    cleanup_expired_uploads,
    cleanup_orphan_staging_dirs,
    init_storage,
    storage_bp,
)
from server.users import users_bp

# ──────────────────────────── Logging ────────────────────────────
#
# logging.basicConfig is intentionally NOT called at module import.
# That would steal logging configuration from any host that imports
# this module (tests, embedding hosts) — `basicConfig` is a one-shot
# operation. `configure_logging()` is called from `main()` instead, and
# create_app() leaves logging alone so importing-as-library is safe.

logger = logging.getLogger("localcloud")


def configure_logging(level: int = logging.WARNING) -> None:
    """Idempotent logging setup; only installs handlers if none exist."""
    if logging.root.handlers:
        return
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


# ──────────────────────────── App Factory ────────────────────────────


def create_app(config: ServerConfig | None = None) -> Quart:
    """Create and configure the Quart application.

    Args:
        config: Server configuration. If None, loads from environment.

    Returns:
        Configured Quart application
    """
    if config is None:
        config = ServerConfig.from_env()

    # Critical #2: Validate config unconditionally — prevents ASGI
    # deployments from starting with weak/empty session_secret
    config.validate()

    # SEC-M3: fail closed if multiple workers are configured. The
    # authoritative rate limiter and SQLite model are per-process; more
    # than one worker silently splits rate-limit state and multiplies the
    # Argon2 concurrency budget. Checked before building anything.
    assert_single_worker()

    app = Quart(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.max_content_length

    # ── Ensure directories exist ──
    # APP-1: must precede db.connect(). sqlite3.connect() does NOT create
    # parent directories, so on a fresh box whose data_dir does not yet
    # exist, opening the DB first raises OperationalError before the dirs
    # would have been created.
    config.ensure_directories()

    # ── Initialize database ──
    db = Database(config.db_path)
    db.connect()
    app.db = db  # type: ignore

    # ── Initialize modules ──
    init_auth(
        db=db,
        session_secret=config.session_secret,
        session_lifetime=config.session_lifetime,
        rate_limit_max=config.rate_limit_max_attempts,
        rate_limit_window=config.rate_limit_window_seconds,
        argon2_max_concurrent=config.argon2_max_concurrent,
    )
    init_storage(
        db=db,
        blob_dir=config.blob_dir,
        staging_dir=config.staging_dir,
        staging_expiry=config.staging_expiry_seconds,
    )

    # ── Typed, immutable app state for handlers (ARCH-H2) ──
    # init_auth / init_storage still populate the module globals that the
    # NON-request-context paths use (the periodic cleanup task and the
    # Argon2 semaphore). Request handlers, however, read this fully-typed
    # snapshot via app_state(), which eliminates the Database|None /
    # str-slot typing suppressions the module globals forced.
    # blob_dir/staging_dir are stored in their realpath'd form (the same
    # value init_storage canonicalizes and the handlers' _safe_path
    # expects).
    store_app_state(
        app,
        AppState(
            db=db,
            blob_dir=os.path.realpath(config.blob_dir),
            staging_dir=os.path.realpath(config.staging_dir),
            staging_expiry=config.staging_expiry_seconds,
            max_chunk_size=DEFAULT_MAX_CHUNK_SIZE,
            session_secret=config.session_secret,
            session_lifetime=config.session_lifetime,
            rate_limit_max=config.rate_limit_max_attempts,
            rate_limit_window=config.rate_limit_window_seconds,
        ),
    )

    # ── Register blueprints ──
    # users_bp (the X25519 enrollment + pubkey directory, item 2C) is
    # registered AFTER storage_bp and BEFORE the forwarded-header
    # assertion below, which must remain the last thing create_app does.
    app.register_blueprint(auth_bp)
    app.register_blueprint(storage_bp)
    app.register_blueprint(users_bp)

    # SEC-M2: fail closed if any forwarded-header / ProxyFix middleware is
    # registered. Peer identity must derive from request.remote_addr
    # UNMODIFIED; a proxy shim that rewrites it from client-controlled
    # headers would let any client spoof its peer identity and defeat
    # session peer-binding + the per-(peer,username) rate limiter. Run
    # after all registration so a middleware added anywhere above is seen.
    assert_no_forwarded_header_middleware(app)

    # ── Security response headers (#17) ──
    @app.after_request
    async def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        # No-store for auth-related endpoints
        if request.path.startswith("/api/auth"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # ── Generic error handlers ──
    # All errors return generic messages to prevent information leakage

    @app.errorhandler(400)
    async def bad_request(e):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(404)
    async def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    async def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(413)
    async def payload_too_large(e):
        return jsonify({"error": "Payload too large"}), 413

    @app.errorhandler(429)
    async def rate_limited(e):
        return jsonify({"error": "Too many requests"}), 429

    @app.errorhandler(500)
    async def internal_error(e):
        # Preserve traceback at WARNING+ level so operators can diagnose
        # without lowering log level globally. Generic message back to
        # the client. (#F12.1)
        logger.exception("Internal error: %s", type(e).__name__)
        return jsonify({"error": "Internal error"}), 500

    # ── Single-worker enforcement at serve time (SEC-M3, defense in depth) ──
    # assert_single_worker() above only reads env vars; `hypercorn --workers N`
    # sets none of them and would silently bypass it. ASGI lifespan startup
    # runs once per worker process, so an exclusive OS lock acquired here makes
    # worker #2 fail closed. Registered BEFORE start_background_tasks so a lost
    # race never spawns the cleanup task. Skipped for an in-memory db (no file
    # to lock); the lockfile must live on a local filesystem.
    @app.before_serving
    async def acquire_single_worker_lock():
        if config.db_path == ":memory:":
            return
        lock_path = f"{config.db_path}.worker.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise RuntimeError(
                f"Another LocalCloud worker already holds {lock_path}. The "
                "authoritative rate limiter and SQLite model are per-process "
                "(SEC-M3); run exactly one worker."
            ) from exc
        app._worker_lock_fd = fd  # type: ignore

    @app.after_serving
    async def release_single_worker_lock():
        fd = getattr(app, "_worker_lock_fd", None)
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            except OSError:
                logger.warning("Failed to release single-worker lock fd")
            app._worker_lock_fd = None  # type: ignore

    # ── Periodic background tasks (#11) ──
    @app.before_serving
    async def start_background_tasks():
        app._cleanup_task = asyncio.create_task(  # type: ignore
            _periodic_cleanup(db, config.rate_limit_window_seconds)
        )

    # ── Shutdown hook ──
    @app.after_serving
    async def shutdown():
        # Cancel background task and await its exit so we don't tear
        # down the DB connection while the cleanup is mid-write. (#F12.2)
        task = getattr(app, "_cleanup_task", None)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                # Cleanup task raised something we didn't anticipate.
                # We're shutting down — log it loudly so it's not silent
                # data loss, but don't block shutdown.
                logger.exception("cleanup task raised on shutdown")
        db.close()
        logger.info("Server shut down")

    logger.info(
        "LocalCloud server initialized, binding to %s:%d",
        config.bind_host,
        config.bind_port,
    )

    return app


async def _periodic_cleanup(db: Database, rate_limit_window: int) -> None:
    """Periodically clean up expired login attempts, staging uploads,
    orphan staging directories, and composite-rate-limiter entries.

    Runs every 60 seconds. Each step is wrapped individually so a
    failure in one cleanup task does not abort the others — earlier
    code aborted the whole tick on the first exception, leaving stale
    state until next iteration. (#85)

    Consecutive failures of the same task are tracked so persistent
    breakage surfaces at ERROR level instead of WARN spam. (#15)
    """
    consecutive_failures = 0
    while True:
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            break

        any_failed = False

        try:
            await asyncio.to_thread(db.cleanup_old_attempts, rate_limit_window)
        except Exception:
            any_failed = True
            logger.warning("cleanup_old_attempts failed", exc_info=True)

        try:
            await asyncio.to_thread(cleanup_expired_uploads)
        except Exception:
            any_failed = True
            logger.warning("cleanup_expired_uploads failed", exc_info=True)

        try:
            await asyncio.to_thread(cleanup_orphan_staging_dirs)
        except Exception:
            any_failed = True
            logger.warning("cleanup_orphan_staging_dirs failed", exc_info=True)

        try:
            await sweep_composite_attempts(rate_limit_window)
        except Exception:
            any_failed = True
            logger.warning("sweep_composite_attempts failed", exc_info=True)

        if any_failed:
            consecutive_failures += 1
            if consecutive_failures >= 10:
                logger.error(
                    "Background cleanup has failed %d consecutive "
                    "iterations — investigate.",
                    consecutive_failures,
                )
        else:
            consecutive_failures = 0


# ──────────────────────────── Entry Point ────────────────────────────


def main() -> None:
    """Run the server. For development only — production uses Hypercorn."""
    import sqlite3

    from shared.exceptions import StorageError

    configure_logging()

    # APP-2: from_env()/_read_secret_file() raise ValueError on a malformed
    # env var or an unreadable/insecure secret file. Previously from_env()
    # ran OUTSIDE any try and dumped an uncaught traceback; load + validate
    # under one fail-closed umbrella so a misconfigured box exits cleanly.
    try:
        config = ServerConfig.from_env()
        config.validate()
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        app = create_app(config)
    except (StorageError, ValueError, RuntimeError, sqlite3.OperationalError) as e:
        # Catches ConfigurationError (StorageError subclass) raised by
        # init_storage when blob_dir/staging_dir are misconfigured
        # (#F12.1 / #23); the RuntimeError raised by the startup invariant
        # assertions (e.g. assert_single_worker on a multi-worker
        # misconfiguration); the re-run config.validate()'s ValueError; and
        # the sqlite3.OperationalError raised by db.connect() when the data
        # dir is unwritable (APP-2) — so a bad deployment exits cleanly
        # fail-closed instead of dumping an uncaught traceback.
        print(f"Startup error: {e}", file=sys.stderr)
        sys.exit(1)

    app.run(
        host=config.bind_host,
        port=config.bind_port,
    )


if __name__ == "__main__":
    main()
