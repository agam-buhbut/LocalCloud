"""Client-side key-management glue tests (item 2C).

Covers the directory-verification helpers that make ``share`` no longer
need an out-of-band recipient pubkey:

    * client/server canonicalize_username byte-identity (parity)
    * build_enroll_signing_input client/server byte-identity (parity)
    * verify_x25519_self_sig: genuine pass; server-substituted X25519,
      absent self-sig, and non-canonical-username self-sig all FAIL closed
    * resolve_recipient: resolves+verifies a genuine directory triple, and
      rejects a server-substituted recipient key / a not-enrolled user

All crypto uses a REAL keystore + the keycore extension (genuine
signatures). The only thing mocked is the HTTP boundary (a tiny fake
exposing ``get_pubkeys``), per the mock-at-I/O-boundary rule.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from client.keymgmt import (
    build_enroll_signing_input,
    resolve_recipient,
    verify_x25519_self_sig,
)
from shared.exceptions import CryptoError
from shared.usernames import canonicalize_username


class _FakeDirectoryClient:
    """Minimal stand-in for CloudClient exposing only get_pubkeys.

    Mirrors the real client's contract: returns a dict of raw bytes with
    empty bytes for absent fields (the real client normalizes the
    all-zero hex sentinel to empty before returning).
    """

    def __init__(self, entry: dict[str, bytes]):
        self._entry = entry
        self.requested: list[str] = []

    def get_pubkeys(self, username: str) -> dict[str, bytes]:
        self.requested.append(username)
        return dict(self._entry)


@pytest.fixture()
def enrolled_keystore(make_keystore: Callable[..., object]):
    """A real keystore plus a genuine enrollment triple for 'alice'."""
    ks = make_keystore()
    username = "alice"
    x = ks.x25519_public_key()  # type: ignore[attr-defined]
    ed = ks.ed25519_public_key()  # type: ignore[attr-defined]
    sig = ks.sign(build_enroll_signing_input(username, x))  # type: ignore[attr-defined]
    return ks, username, ed, x, sig


# ──────────────────────────── parity ────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("alice", "alice"),
        ("Alice", "alice"),
        ("  ALICE  ", "alice"),
        ("ＡＬＩＣＥ", "alice"),  # fullwidth NFKC
        ("BoB.123", "bob.123"),
        ("user_name-1", "user_name-1"),
    ],
)
def test_client_server_canonicalize_parity(raw: str, expected: str):
    """The client and server share ONE canonicalizer — assert output.

    server.auth imports the same shared function under its private name;
    both must yield identical bytes for the enroll signature to verify.
    """
    from server.auth import _canonicalize_username as server_canon

    client_out = canonicalize_username(raw)
    server_out = server_canon(raw)
    assert client_out == server_out == expected
    assert client_out.encode("utf-8") == server_out.encode("utf-8")


def test_enroll_signing_input_client_server_parity():
    """build_enroll_signing_input is byte-identical to the server's.

    server/users.py imports the same shared builder; feed both the same
    canonical username + key and assert identical bytes.
    """
    from shared.usernames import build_enroll_signing_input as server_builder

    x = b"\x42" * 32
    assert build_enroll_signing_input("alice", x) == server_builder("alice", x)


def test_enroll_signing_input_format():
    """Fixed-width / length-prefixed encoding, domain-separated prefix."""
    import struct

    x = b"\x07" * 32
    out = build_enroll_signing_input("alice", x)
    assert out.startswith(b"localcloud-x25519-enroll-v1")
    rest = out[len(b"localcloud-x25519-enroll-v1") :]
    (name_len,) = struct.unpack(">H", rest[:2])
    assert name_len == len(b"alice")
    assert rest[2 : 2 + name_len] == b"alice"
    assert rest[2 + name_len :] == x


def test_enroll_signing_input_rejects_bad_key_len():
    with pytest.raises(ValueError):
        build_enroll_signing_input("alice", b"\x00" * 31)


# ──────────────────────── verify_x25519_self_sig ────────────────────────


def test_verify_genuine_triple(enrolled_keystore):
    _ks, username, ed, x, sig = enrolled_keystore
    assert verify_x25519_self_sig(ed, x, sig, username) is True


def test_verify_rejects_substituted_x25519(enrolled_keystore):
    """A server-substituted X25519 (real ed25519, real sig) FAILS."""
    _ks, username, ed, x, sig = enrolled_keystore
    substituted = bytes((b ^ 0xFF) for b in x)
    assert verify_x25519_self_sig(ed, substituted, sig, username) is False


def test_verify_rejects_absent_self_sig(enrolled_keystore):
    _ks, username, ed, x, _sig = enrolled_keystore
    assert verify_x25519_self_sig(ed, x, b"\x00" * 64, username) is False


def test_verify_rejects_non_canonical_username(enrolled_keystore):
    """A sig made over a DIFFERENT username does not verify for 'alice'."""
    _ks, _username, ed, x, sig = enrolled_keystore
    assert verify_x25519_self_sig(ed, x, sig, "bob") is False


def test_verify_rejects_wrong_lengths(enrolled_keystore):
    _ks, username, ed, x, sig = enrolled_keystore
    assert verify_x25519_self_sig(ed[:-1], x, sig, username) is False
    assert verify_x25519_self_sig(ed, x[:-1], sig, username) is False
    assert verify_x25519_self_sig(ed, x, sig[:-1], username) is False


# ──────────────────────────── resolve_recipient ────────────────────────────


def test_resolve_recipient_verifies_genuine(enrolled_keystore):
    """resolve_recipient returns the verified X25519 for a genuine triple."""
    _ks, username, ed, x, sig = enrolled_keystore
    fake = _FakeDirectoryClient({"ed25519": ed, "x25519": x, "self_sig": sig})
    resolved = resolve_recipient(fake, username)
    assert resolved == x
    # The username passed to the directory is canonical.
    assert fake.requested == [username]


def test_resolve_recipient_rejects_substituted_key(enrolled_keystore):
    """A server-substituted X25519 (with the victim's real ed25519/sig)
    is rejected fail-closed — this is the whole point of 2C.
    """
    _ks, username, ed, x, sig = enrolled_keystore
    substituted = bytes((b ^ 0xFF) for b in x)
    fake = _FakeDirectoryClient({"ed25519": ed, "x25519": substituted, "self_sig": sig})
    with pytest.raises(CryptoError, match="self-signature"):
        resolve_recipient(fake, username)


def test_resolve_recipient_rejects_not_enrolled(enrolled_keystore):
    """Absent fields (not enrolled) → CryptoError, never a silent pass."""
    _ks, username, ed, _x, _sig = enrolled_keystore
    fake = _FakeDirectoryClient({"ed25519": ed, "x25519": b"", "self_sig": b""})
    with pytest.raises(CryptoError, match="not enrolled"):
        resolve_recipient(fake, username)


def test_resolve_recipient_rejects_invalid_username():
    fake = _FakeDirectoryClient({"ed25519": b"", "x25519": b"", "self_sig": b""})
    with pytest.raises(CryptoError, match="Invalid recipient username"):
        resolve_recipient(fake, "ab")  # too short for the charset rule


def test_resolve_recipient_canonicalizes_before_lookup(enrolled_keystore):
    """A non-canonical input is canonicalized before the directory call
    AND before the signature check, so a genuine 'alice' triple verifies
    when the caller passes 'ALICE'.
    """
    _ks, username, ed, x, sig = enrolled_keystore
    fake = _FakeDirectoryClient({"ed25519": ed, "x25519": x, "self_sig": sig})
    resolved = resolve_recipient(fake, "ALICE")
    assert resolved == x
    assert fake.requested == ["alice"]
