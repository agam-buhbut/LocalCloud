"""Startup fail-closed invariants for the rate-limit / peer-binding model.

SEC-M2 — peer identity must come from ``request.remote_addr`` UNMODIFIED;
NO forwarded-header / ProxyFix middleware may be registered (it would let
a client spoof its peer identity and defeat session peer-binding + the
per-(peer,username) rate limiter).

SEC-M3 — the authoritative in-memory rate limiter and the per-process
SQLite model are single-worker. More than one worker silently splits the
rate-limit state and Argon2 concurrency budget, so startup must FAIL
CLOSED when multiple workers are configured.
"""

from __future__ import annotations

import pytest
from quart import Quart

from server.auth import (
    _get_peer_identity,
    assert_no_forwarded_header_middleware,
    assert_single_worker,
)

# ──────────────────────────── SEC-M2: forwarded-header ban ────────────────────────────


def test_default_app_has_no_forwarded_middleware():
    """A freshly-built Quart app passes the forwarded-header assertion."""
    app = Quart(__name__)
    # Must not raise.
    assert_no_forwarded_header_middleware(app)


def test_assertion_fires_on_proxyfix_like_middleware():
    """A ProxyFix-style ASGI wrapper trips the fail-closed assertion."""

    class ProxyFix:  # name intentionally mirrors werkzeug's middleware
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            await self.app(scope, receive, send)

    app = Quart(__name__)
    app.asgi_app = ProxyFix(app.asgi_app)  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="(?i)forwarded|proxy"):
        assert_no_forwarded_header_middleware(app)


def test_assertion_fires_on_forwarded_header_middleware():
    """A generic forwarded-header middleware also trips the assertion."""

    class ForwardedHeaderMiddleware:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            await self.app(scope, receive, send)

    app = Quart(__name__)
    app.asgi_app = ForwardedHeaderMiddleware(app.asgi_app)  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="(?i)forwarded|proxy"):
        assert_no_forwarded_header_middleware(app)


def test_assertion_detects_nested_forwarded_middleware():
    """A forwarded-header middleware buried under a benign wrapper is caught."""

    class ProxyFix:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            await self.app(scope, receive, send)

    class BenignWrapper:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            await self.app(scope, receive, send)

    app = Quart(__name__)
    app.asgi_app = BenignWrapper(ProxyFix(app.asgi_app))  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="(?i)forwarded|proxy"):
        assert_no_forwarded_header_middleware(app)


def test_benign_middleware_does_not_trip_assertion():
    """A non-forwarding wrapper must not be flagged (no false positive)."""

    class GzipMiddleware:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            await self.app(scope, receive, send)

    app = Quart(__name__)
    app.asgi_app = GzipMiddleware(app.asgi_app)  # type: ignore[assignment]

    # Must not raise — only forwarded/proxy middleware is banned.
    assert_no_forwarded_header_middleware(app)


# ──────────────────────────── SEC-M2: remote_addr is unmodified ────────────────────────────
#
# Quart's test_request_context does not wire the ASGI scope's ``client``
# field into ``request.remote_addr`` (that bridge only runs under a real
# ASGI server), so we set ``remote_addr`` explicitly on the live request
# object inside the context and assert _get_peer_identity returns exactly
# that — proving it reads remote_addr and ignores forwarded headers.


from quart import request  # noqa: E402  (placed with its use)


async def _peer_with(
    app: Quart, headers: dict[str, str], remote_addr: str | None
) -> str:
    async with app.test_request_context(
        "/api/auth/login",
        method="POST",
        headers=headers,
    ):
        real = request._get_current_object()  # type: ignore[attr-defined]
        object.__setattr__(real, "remote_addr", remote_addr)
        return _get_peer_identity()


async def test_peer_identity_ignores_x_forwarded_for():
    """_get_peer_identity must ignore X-Forwarded-For / Forwarded headers."""
    app = Quart(__name__)
    peer = await _peer_with(
        app,
        headers={"X-Forwarded-For": "1.2.3.4", "Forwarded": "for=5.6.7.8"},
        remote_addr="10.0.0.2",
    )
    assert peer == "10.0.0.2", "peer must come from remote_addr, not XFF"


async def test_peer_identity_is_remote_addr_value():
    """With no forwarded headers, peer is exactly remote_addr."""
    app = Quart(__name__)
    peer = await _peer_with(app, headers={}, remote_addr="10.0.0.9")
    assert peer == "10.0.0.9"


async def test_peer_identity_empty_when_remote_addr_missing():
    """A missing remote_addr yields empty peer even with forwarded headers."""
    app = Quart(__name__)
    peer = await _peer_with(
        app,
        headers={"X-Forwarded-For": "9.9.9.9"},
        remote_addr=None,
    )
    assert peer == "", "no remote_addr must NOT fall back to a forwarded header"


# ──────────────────────────── SEC-M3: single-worker fail-closed ────────────────────────────


def test_single_worker_passes_when_unset(monkeypatch: pytest.MonkeyPatch):
    for var in ("WEB_CONCURRENCY", "HYPERCORN_WORKERS", "LOCALCLOUD_WORKERS"):
        monkeypatch.delenv(var, raising=False)
    # Must not raise.
    assert_single_worker()


def test_single_worker_passes_when_one(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    assert_single_worker()


def test_multi_worker_fails_closed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    with pytest.raises(RuntimeError, match="(?i)single.?worker|worker"):
        assert_single_worker()


def test_multi_worker_fails_closed_alt_var(monkeypatch: pytest.MonkeyPatch):
    for var in ("WEB_CONCURRENCY", "HYPERCORN_WORKERS", "LOCALCLOUD_WORKERS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HYPERCORN_WORKERS", "2")
    with pytest.raises(RuntimeError, match="(?i)worker"):
        assert_single_worker()


def test_invalid_worker_value_fails_closed(monkeypatch: pytest.MonkeyPatch):
    """A non-integer worker count must fail closed, not be ignored."""
    for var in ("WEB_CONCURRENCY", "HYPERCORN_WORKERS", "LOCALCLOUD_WORKERS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOCALCLOUD_WORKERS", "not-a-number")
    with pytest.raises(RuntimeError, match="(?i)worker"):
        assert_single_worker()


# ──────────────────────────── create_app wiring (integration) ────────────────────────────


def _config_for(tmp_data_dir, session_secret):
    from server.config import ServerConfig

    return ServerConfig(
        bind_host="10.0.0.1",
        data_dir=str(tmp_data_dir),
        blob_dir=str(tmp_data_dir / "blobs"),
        staging_dir=str(tmp_data_dir / "staging"),
        db_path=str(tmp_data_dir / "meta.db"),
        session_secret=session_secret,
    )


def test_create_app_succeeds_single_worker(
    tmp_data_dir, session_secret, monkeypatch: pytest.MonkeyPatch
):
    """create_app builds cleanly under the default single-worker model."""
    for var in ("WEB_CONCURRENCY", "HYPERCORN_WORKERS", "LOCALCLOUD_WORKERS"):
        monkeypatch.delenv(var, raising=False)
    from server.app import create_app

    app = create_app(_config_for(tmp_data_dir, session_secret))
    try:
        assert app is not None
        # The wired forwarded-header assertion already ran inside
        # create_app; re-running it here must still pass.
        assert_no_forwarded_header_middleware(app)
    finally:
        db = getattr(app, "db", None)
        if db is not None:
            db.close()


def test_create_app_fails_closed_multi_worker(
    tmp_data_dir, session_secret, monkeypatch: pytest.MonkeyPatch
):
    """create_app refuses to build when multiple workers are configured."""
    monkeypatch.setenv("WEB_CONCURRENCY", "3")
    from server.app import create_app

    with pytest.raises(RuntimeError, match="(?i)worker"):
        create_app(_config_for(tmp_data_dir, session_secret))


# ──────────────────────────── APP-1: directories created before DB open ────────────────────────────
#
# sqlite3.connect() does NOT create parent directories — on a fresh box
# whose configured data_dir does not yet exist, opening the DB before
# create_app calls config.ensure_directories() raises OperationalError.
# ensure_directories() must therefore run BEFORE db.connect().


def test_create_app_creates_missing_data_dir(
    tmp_path, session_secret, monkeypatch: pytest.MonkeyPatch
):
    """create_app builds when the configured data_dir does not pre-exist.

    The data_dir (and its parent) are absent up front; create_app must
    create the directory tree and open the DB inside it, rather than
    raising sqlite3.OperationalError on the unborn path. (APP-1)
    """
    for var in ("WEB_CONCURRENCY", "HYPERCORN_WORKERS", "LOCALCLOUD_WORKERS"):
        monkeypatch.delenv(var, raising=False)
    from server.app import create_app
    from server.config import ServerConfig

    fresh = tmp_path / "absent-parent" / "data"
    assert not fresh.exists()
    config = ServerConfig(
        bind_host="10.0.0.1",
        data_dir=str(fresh),
        blob_dir=str(fresh / "blobs"),
        staging_dir=str(fresh / "staging"),
        db_path=str(fresh / "meta.db"),
        session_secret=session_secret,
    )

    app = create_app(config)
    try:
        assert app is not None
        assert fresh.is_dir()
        assert (fresh / "blobs").is_dir()
        assert (fresh / "staging").is_dir()
    finally:
        db = getattr(app, "db", None)
        if db is not None:
            db.close()


# ──────────────────────────── APP-2: main() fail-closed startup ────────────────────────────
#
# The dev-only main() must surface config/secret-file/db-open failures as a
# clean stderr message + nonzero exit, never as an uncaught traceback.


def test_main_exits_clean_on_bad_env_config(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """A malformed env var makes ServerConfig.from_env() raise ValueError;
    main() must catch it and exit cleanly rather than dump a traceback. (APP-2)
    """
    monkeypatch.setenv("LOCALCLOUD_BIND_PORT", "not-an-int")
    from server.app import main

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    assert "Configuration error" in capsys.readouterr().err


def test_main_exits_clean_on_db_open_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """A sqlite3.OperationalError from create_app()'s db.connect() must be
    caught by main() and surfaced as a clean fail-closed exit. (APP-2)
    """
    import sqlite3

    for var in ("WEB_CONCURRENCY", "HYPERCORN_WORKERS", "LOCALCLOUD_WORKERS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOCALCLOUD_SESSION_SECRET", "a" * 64)

    import server.app as app_module

    def _boom(_config: object) -> None:
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(app_module, "create_app", _boom)

    with pytest.raises(SystemExit) as exc:
        app_module.main()
    assert exc.value.code == 1
    assert "Startup error" in capsys.readouterr().err
