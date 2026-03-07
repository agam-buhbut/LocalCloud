from __future__ import annotations

import asyncio
import logging
import os
import sys

from quart import Quart, jsonify, request

from server.auth import auth_bp, init_auth
from server.config import ServerConfig
from server.database import Database
from server.storage import init_storage, storage_bp

# ──────────────────────────── Logging ────────────────────────────

# Minimal security logging only — no plaintext, no metadata content
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("localcloud")


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

    app = Quart(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.max_content_length

    # ── Initialize database ──
    db = Database(config.db_path)
    db.connect()
    app.db = db  # type: ignore

    # ── Ensure directories exist ──
    config.ensure_directories()

    # ── Initialize modules ──
    init_auth(
        db=db,
        session_secret=config.session_secret,
        session_lifetime=config.session_lifetime,
        rate_limit_max=config.rate_limit_max_attempts,
        rate_limit_window=config.rate_limit_window_seconds,
    )
    init_storage(
        db=db,
        blob_dir=config.blob_dir,
        staging_dir=config.staging_dir,
        staging_expiry=config.staging_expiry_seconds,
    )

    # ── Register blueprints ──
    app.register_blueprint(auth_bp)
    app.register_blueprint(storage_bp)

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
        logger.error("Internal error: %s", type(e).__name__)
        return jsonify({"error": "Internal error"}), 500

    # ── Periodic background tasks (#11) ──
    @app.before_serving
    async def start_background_tasks():
        app._cleanup_task = asyncio.create_task(  # type: ignore
            _periodic_cleanup(db, config.rate_limit_window_seconds)
        )

    # ── Shutdown hook ──
    @app.after_serving
    async def shutdown():
        # Cancel background tasks
        if hasattr(app, "_cleanup_task"):
            app._cleanup_task.cancel()  # type: ignore
        db.close()
        logger.info("Server shut down")

    logger.info(
        "LocalCloud server initialized, binding to %s:%d",
        config.bind_host,
        config.bind_port,
    )

    return app


async def _periodic_cleanup(db: Database, rate_limit_window: int) -> None:
    """Periodically clean up expired login attempts and staging uploads.

    Runs every 60 seconds to avoid O(table) scans on each login request (#11).
    """
    from server.storage import cleanup_expired_uploads

    while True:
        try:
            await asyncio.sleep(60)
            await asyncio.to_thread(db.cleanup_old_attempts, rate_limit_window)
            await asyncio.to_thread(cleanup_expired_uploads)
        except asyncio.CancelledError:
            break
        except Exception:
            logger.warning("Background cleanup error", exc_info=True)


# ──────────────────────────── Entry Point ────────────────────────────


def main():
    """Run the server. For development only — production uses Hypercorn."""
    config = ServerConfig.from_env()

    # Validate config before starting
    try:
        config.validate()
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    app = create_app(config)
    app.run(
        host=config.bind_host,
        port=config.bind_port,
    )


if __name__ == "__main__":
    main()
