"""ServerConfig parsing/validation for the Argon2 concurrency knob (4F)."""

from __future__ import annotations

import pytest

from server.config import ServerConfig

_VALID_SECRET = "a" * 64


def _valid_config() -> ServerConfig:
    cfg = ServerConfig()
    cfg.session_secret = _VALID_SECRET
    return cfg


def test_argon2_default_is_four() -> None:
    assert ServerConfig().argon2_max_concurrent == 4


def test_from_env_reads_argon2_max_concurrent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LOCALCLOUD_SESSION_SECRET", _VALID_SECRET)
    monkeypatch.setenv("LOCALCLOUD_ARGON2_MAX_CONCURRENT", "7")
    cfg = ServerConfig.from_env()
    assert cfg.argon2_max_concurrent == 7


def test_validate_accepts_valid_argon2_value() -> None:
    cfg = _valid_config()
    cfg.argon2_max_concurrent = 2
    cfg.validate()  # must not raise


def test_validate_rejects_zero_argon2_value() -> None:
    cfg = _valid_config()
    cfg.argon2_max_concurrent = 0
    with pytest.raises(ValueError, match="argon2_max_concurrent"):
        cfg.validate()


# ── Peer-identity invariant (F8, hybrid): the box must refuse to run reachable
# off the WireGuard tunnel. Identity == request.remote_addr is only sound when
# the only reachable path is the WG interface, so a public/unspecified bind
# fails closed unless the operator explicitly overrides. ──


def test_validate_rejects_unspecified_bind() -> None:
    cfg = _valid_config()
    cfg.bind_host = "0.0.0.0"  # noqa: S104 — testing that this is REJECTED
    with pytest.raises(ValueError, match="non-WireGuard"):
        cfg.validate()


def test_validate_rejects_public_bind() -> None:
    cfg = _valid_config()
    cfg.bind_host = "8.8.8.8"
    with pytest.raises(ValueError, match="public address"):
        cfg.validate()


def test_validate_allows_private_bind() -> None:
    cfg = _valid_config()
    cfg.bind_host = "10.0.0.1"  # the WireGuard tunnel address
    cfg.validate()  # must not raise


def test_validate_allows_loopback_bind() -> None:
    cfg = _valid_config()
    cfg.bind_host = "127.0.0.1"
    cfg.validate()  # must not raise


def test_public_bind_override_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALCLOUD_ALLOW_PUBLIC_BIND", "1")
    cfg = _valid_config()
    cfg.bind_host = "8.8.8.8"
    cfg.validate()  # override allows it


# ── M-2 (pentest): warn that a non-loopback bind must be the WireGuard
# interface (the app is plain HTTP). ──


def test_validate_warns_on_non_loopback_bind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    cfg = _valid_config()
    cfg.bind_host = "10.0.0.1"  # a private IP — allowed, but not necessarily WG
    with caplog.at_level(logging.WARNING, logger="localcloud.config"):
        cfg.validate()
    assert "PLAIN HTTP" in caplog.text and "WireGuard" in caplog.text


def test_validate_does_not_warn_on_loopback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    cfg = _valid_config()
    cfg.bind_host = "127.0.0.1"
    with caplog.at_level(logging.WARNING, logger="localcloud.config"):
        cfg.validate()
    assert "PLAIN HTTP" not in caplog.text


# ── L-1 (pentest): ensure_directories re-tightens a pre-existing loose dir. ──


def test_ensure_directories_tightens_existing(tmp_path) -> None:
    import os
    import stat

    d = tmp_path / "data"
    d.mkdir(mode=0o777)
    os.chmod(d, 0o777)  # simulate a pre-existing world-accessible data dir
    cfg = _valid_config()
    cfg.data_dir = str(d)
    cfg.blob_dir = str(d / "blobs")
    cfg.staging_dir = str(d / "staging")
    cfg.ensure_directories()
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


# ── D2 (pentest 2026-06-28): _read_secret_file must accept systemd's 0440 ──
# LoadCredential file (group-owned by the service group) while still rejecting
# world access and group write. Hardware finding: the old `& 0o077` check made
# the recommended `LoadCredential=` deploy unable to start.


def _write_secret(tmp_path, mode: int):
    import os

    p = tmp_path / "session.secret"
    p.write_text("b" * 64)
    os.chmod(p, mode)
    return p


def test_read_secret_accepts_0400(tmp_path) -> None:
    from server.config import _read_secret_file

    assert _read_secret_file(str(_write_secret(tmp_path, 0o400))) == "b" * 64


def test_read_secret_accepts_0600(tmp_path) -> None:
    from server.config import _read_secret_file

    assert _read_secret_file(str(_write_secret(tmp_path, 0o600))) == "b" * 64


def test_read_secret_accepts_0440_own_group(tmp_path) -> None:
    # systemd LoadCredential delivers the secret at mode 0440 group-owned by the
    # service group; a temp file's group defaults to the test process's egid.
    from server.config import _read_secret_file

    assert _read_secret_file(str(_write_secret(tmp_path, 0o440))) == "b" * 64


def test_read_secret_rejects_world_readable(tmp_path) -> None:
    from server.config import _read_secret_file

    with pytest.raises(ValueError, match="world-accessible"):
        _read_secret_file(str(_write_secret(tmp_path, 0o444)))


def test_read_secret_rejects_group_writable(tmp_path) -> None:
    from server.config import _read_secret_file

    with pytest.raises(ValueError, match="group-writable"):
        _read_secret_file(str(_write_secret(tmp_path, 0o660)))
