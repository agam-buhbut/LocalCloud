"""F3: runtime single-process lock (server/app.py).

assert_single_worker() only reads env vars and is blind to
``hypercorn --workers N``. The per-process flock acquired in before_serving
catches that bypass: ASGI lifespan startup runs once per worker, so a second
worker on the same db_path fails closed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from server.app import create_app
from server.config import ServerConfig


def _cfg(d: Path, secret: str) -> ServerConfig:
    (d / "blobs").mkdir(exist_ok=True)
    (d / "staging").mkdir(exist_ok=True)
    return ServerConfig(
        bind_host="10.0.0.1",
        data_dir=str(d),
        blob_dir=str(d / "blobs"),
        staging_dir=str(d / "staging"),
        db_path=str(d / "meta.db"),
        session_secret=secret,
    )


def _clear_worker_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("WEB_CONCURRENCY", "HYPERCORN_WORKERS", "LOCALCLOUD_WORKERS"):
        monkeypatch.delenv(var, raising=False)


async def test_single_worker_starts_and_stops(
    tmp_path: Path, session_secret: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_worker_env(monkeypatch)
    app = create_app(_cfg(tmp_path, session_secret))
    await app.startup()
    await app.shutdown()  # releases the lock + closes the DB


async def test_second_worker_fails_closed(
    tmp_path: Path, session_secret: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_worker_env(monkeypatch)
    app1 = create_app(_cfg(tmp_path, session_secret))
    app2 = create_app(_cfg(tmp_path, session_secret))  # SAME db_path
    await app1.startup()
    try:
        with pytest.raises(RuntimeError, match="SEC-M3"):
            await app2.startup()
    finally:
        await app1.shutdown()  # closes app1.db, releases the lock
        db2 = getattr(app2, "db", None)
        if db2 is not None:
            db2.close()


async def test_lock_released_allows_restart(
    tmp_path: Path, session_secret: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_worker_env(monkeypatch)
    app1 = create_app(_cfg(tmp_path, session_secret))
    await app1.startup()
    await app1.shutdown()  # release
    # A fresh process (new app, same db_path) can now acquire the lock again.
    app2 = create_app(_cfg(tmp_path, session_secret))
    await app2.startup()
    await app2.shutdown()
