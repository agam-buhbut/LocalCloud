"""Admin CLI tests.

Covers the operator-side create/disable/quota/register-pubkey/list flows
that user-state mutation now MUST go through (no HTTP endpoint exposes
these). See server/admin.py.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from server import admin
from server.config import ServerConfig
from server.database import Database


@pytest.fixture()
def env_config(tmp_path: Path, monkeypatch):
    """Point ServerConfig.from_env() at a fresh tmp DB."""
    db_path = tmp_path / "meta.db"
    blob_dir = tmp_path / "blobs"
    staging_dir = tmp_path / "staging"
    blob_dir.mkdir()
    staging_dir.mkdir()
    monkeypatch.setenv("LOCALCLOUD_DB_PATH", str(db_path))
    monkeypatch.setenv("LOCALCLOUD_BLOB_DIR", str(blob_dir))
    monkeypatch.setenv("LOCALCLOUD_STAGING_DIR", str(staging_dir))
    monkeypatch.setenv("LOCALCLOUD_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LOCALCLOUD_SESSION_SECRET", "x" * 64)
    return ServerConfig.from_env()


@pytest.fixture()
def db(env_config: ServerConfig) -> Database:
    d = Database(env_config.db_path)
    d.connect()
    return d


def _run_with_passwords(args, password="correct-horse-battery"):
    with patch.object(admin.getpass, "getpass", side_effect=[password, password]):
        return admin.main(args)


def test_create_user_happy_path(env_config, db, capsys):
    rc = _run_with_passwords(["create-user", "alice", "--quota", "1048576"])
    assert rc == 0
    user = db.get_user_by_username("alice")
    assert user is not None
    assert user["quota_bytes"] == 1048576
    assert user["is_active"] == 1


def test_create_user_duplicate_fails(env_config, db, capsys):
    _run_with_passwords(["create-user", "alice"])
    rc = _run_with_passwords(["create-user", "alice"])
    assert rc == 1


def test_create_user_password_mismatch_fails(env_config, db):
    with patch.object(admin.getpass, "getpass", side_effect=["one", "two"]):
        rc = admin.main(["create-user", "bob"])
    assert rc == 1
    assert db.get_user_by_username("bob") is None


def test_create_user_short_password_rejected(env_config, db):
    with patch.object(admin.getpass, "getpass", side_effect=["short", "short"]):
        rc = admin.main(["create-user", "carol"])
    assert rc == 1


def test_create_user_canonicalizes_username(env_config, db):
    """Fullwidth input collapses to lowercase ASCII."""
    rc = _run_with_passwords(["create-user", "ＡＤＭＩＮ"])
    assert rc == 0
    assert db.get_user_by_username("admin") is not None


def test_create_user_rejects_bad_username(env_config, db):
    with (
        patch.object(
            admin.getpass,
            "getpass",
            side_effect=["correct-horse-battery", "correct-horse-battery"],
        ),
        pytest.raises(ValueError),
    ):
        admin.main(["create-user", "ab"])  # too short


def test_register_pubkey_sets_key_and_bumps_session(env_config, db):
    _run_with_passwords(["create-user", "alice"])
    pubkey_hex = os.urandom(32).hex()
    rc = admin.main(["register-pubkey", "alice", pubkey_hex])
    assert rc == 0

    user = db.get_user_by_username("alice")
    assert user is not None
    assert user["ed25519_pubkey"] == bytes.fromhex(pubkey_hex)
    # Bumped from 1 → 2
    assert user["session_version"] == 2


def test_register_pubkey_wrong_length_rejected(env_config, db):
    _run_with_passwords(["create-user", "alice"])
    rc = admin.main(["register-pubkey", "alice", "abcd"])
    assert rc == 1


def test_register_pubkey_unknown_user_rejected(env_config, db):
    rc = admin.main(["register-pubkey", "nobody", os.urandom(32).hex()])
    assert rc == 1


def test_disable_user(env_config, db):
    _run_with_passwords(["create-user", "alice"])
    rc = admin.main(["disable-user", "alice"])
    assert rc == 0
    user = db.get_user_by_username("alice")
    assert user is not None
    assert user["is_active"] == 0
    # disable_user bumps session_version atomically
    assert user["session_version"] == 2


def test_disable_user_unknown_rejected(env_config, db):
    rc = admin.main(["disable-user", "nobody"])
    assert rc == 1


def test_set_quota(env_config, db):
    _run_with_passwords(["create-user", "alice"])
    rc = admin.main(["set-quota", "alice", "9999999"])
    assert rc == 0
    user = db.get_user_by_username("alice")
    assert user is not None
    assert user["quota_bytes"] == 9999999


def test_bump_session_revokes(env_config, db):
    _run_with_passwords(["create-user", "alice"])
    initial = db.get_user_by_username("alice")["session_version"]
    rc = admin.main(["bump-session", "alice"])
    assert rc == 0
    after = db.get_user_by_username("alice")["session_version"]
    assert after == initial + 1


def test_list_users(env_config, db, capsys):
    _run_with_passwords(["create-user", "alice"])
    _run_with_passwords(["create-user", "bob"])
    rc = admin.main(["list-users"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "alice" in captured.out
    assert "bob" in captured.out
