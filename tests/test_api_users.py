"""Route-level integration tests for the user directory surface (item 2C).

Exercises the X25519 enrollment + pubkey directory endpoints end-to-end
through the Quart test client:

    POST /api/users/enroll_x25519
    GET  /api/users/<username>/pubkeys
    GET  /api/users/enrolled

These are REAL guards: enrollment round-trips through the live DB, the
self-signature is produced by a genuine keystore and re-verified by the
server, and the directory's uniform-response property is asserted on both
SHAPE and byte-LENGTH for unknown / keyless / enrolled users. A focused
timing test asserts the constant-deadline envelope is actually applied.

The ``fast_directory`` fixture shrinks the directory timing budget so the
non-timing tests don't each pay the production 150 ms sleep; the dedicated
timing test patches it to a known floor and measures.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

import pytest

import server.users as users_mod
from client.keymgmt import build_enroll_signing_input
from tests.conftest import KeyedClient


@pytest.fixture()
def fast_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink the directory constant-deadline so tests run fast.

    The uniform-response *shape/length* property is independent of the
    budget; only the dedicated timing test cares about the actual value.
    """
    monkeypatch.setattr(users_mod, "_DIRECTORY_TIMING_BUDGET_S", 0.0)


async def _enroll(authed, keystore, username: str):
    """Enroll ``keystore``'s X25519 key for ``username`` over HTTP.

    Builds the genuine self-signature with the keystore's Ed25519 key.
    Returns the raw HTTP response.
    """
    x = keystore.x25519_public_key()  # type: ignore[attr-defined]
    sig = keystore.sign(build_enroll_signing_input(username, x))  # type: ignore[attr-defined]
    return await authed.post(
        "/api/users/enroll_x25519",
        json={"x25519_pubkey": x.hex(), "self_sig": sig.hex()},
    )


# ──────────────────────────── enrollment ────────────────────────────


async def test_enroll_roundtrip_directory_returns_key(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    fast_directory: None,
):
    """Enroll → directory returns exactly the enrolled X25519 + self-sig."""
    kc = await make_keyed_client()
    resp = await _enroll(kc.authed, kc.keystore, kc.username)
    assert resp.status_code == 200, await resp.get_data()
    assert (await resp.get_json()) == {"status": "enrolled"}

    look = await kc.authed.get(f"/api/users/{kc.username}/pubkeys")
    assert look.status_code == 200
    body = await look.get_json()
    assert bytes.fromhex(body["x25519"]) == kc.keystore.x25519_public_key()  # type: ignore[attr-defined]
    assert bytes.fromhex(body["ed25519"]) == kc.keystore.ed25519_public_key()  # type: ignore[attr-defined]
    # self_sig must verify against the returned ed25519 over the canonical
    # username — i.e. the stored triple is internally consistent.
    from client.keymgmt import verify_x25519_self_sig

    assert verify_x25519_self_sig(
        bytes.fromhex(body["ed25519"]),
        bytes.fromhex(body["x25519"]),
        bytes.fromhex(body["self_sig"]),
        kc.username,
    )


async def test_enroll_rejects_substituted_x25519(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    fast_directory: None,
):
    """A self-sig that doesn't match the submitted X25519 → generic 400.

    Models a hostile/buggy client (or server substitution attempt at
    enroll time): the signature is over the real key but a DIFFERENT key
    is submitted, so the server's defense-in-depth verify fails.
    """
    kc = await make_keyed_client()
    real_x = kc.keystore.x25519_public_key()  # type: ignore[attr-defined]
    sig = kc.keystore.sign(build_enroll_signing_input(kc.username, real_x))  # type: ignore[attr-defined]
    substituted = bytes((b ^ 0xFF) for b in real_x)
    resp = await kc.authed.post(
        "/api/users/enroll_x25519",
        json={"x25519_pubkey": substituted.hex(), "self_sig": sig.hex()},
    )
    assert resp.status_code == 400
    assert (await resp.get_json()) == {"error": "Invalid request"}


async def test_enroll_rejects_non_canonical_username_sig(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    fast_directory: None,
):
    """A self-sig bound to a username OTHER than the caller's → 400.

    The server rebuilds the signing input over the CALLER's canonical
    username; a signature made over a different name cannot verify, so a
    self-sig cannot be lifted onto another account.
    """
    kc = await make_keyed_client()
    x = kc.keystore.x25519_public_key()  # type: ignore[attr-defined]
    # Sign over a different (canonical) username than the caller's.
    wrong_sig = kc.keystore.sign(build_enroll_signing_input("someone-else", x))  # type: ignore[attr-defined]
    resp = await kc.authed.post(
        "/api/users/enroll_x25519",
        json={"x25519_pubkey": x.hex(), "self_sig": wrong_sig.hex()},
    )
    assert resp.status_code == 400


async def test_enroll_no_ed25519_returns_generic_400(
    client,
    make_user: Callable[..., str],
    make_keystore: Callable[..., object],
    fast_argon2: None,
    fast_directory: None,
):
    """A caller with NO Ed25519 on file gets the generic 400 (not a 409).

    Per the addendum, the keyless case is folded into the uniform 400.
    """
    from tests.conftest import TEST_PASSWORD, AuthedClient, _login

    # User created WITHOUT an ed25519_pubkey.
    make_user(username="noid", password=TEST_PASSWORD, ed25519_pubkey=b"")
    token = await _login(client, "noid", TEST_PASSWORD, peer_host="10.0.0.7")
    authed = AuthedClient(client=client, token=token, peer_host="10.0.0.7")

    ks = make_keystore()
    resp = await _enroll(authed, ks, "noid")
    assert resp.status_code == 400
    assert (await resp.get_json()) == {"error": "Invalid request"}


@pytest.mark.parametrize(
    "body",
    [
        {"x25519_pubkey": "zz", "self_sig": "00" * 64},  # bad hex
        {"x25519_pubkey": "11" * 16, "self_sig": "00" * 64},  # x too short
        {"x25519_pubkey": "11" * 32, "self_sig": "00" * 32},  # sig too short
        {"self_sig": "00" * 64},  # missing field
        {},  # empty
    ],
)
async def test_enroll_rejects_malformed_body(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    fast_directory: None,
    body: dict,
):
    """Bad hex / wrong lengths / missing fields all → generic 400."""
    kc = await make_keyed_client()
    resp = await kc.authed.post("/api/users/enroll_x25519", json=body)
    assert resp.status_code == 400
    assert (await resp.get_json()) == {"error": "Invalid request"}


async def test_enroll_row_not_updated_returns_generic_400(
    app,
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    fast_directory: None,
    monkeypatch: pytest.MonkeyPatch,
):
    """If the persist UPDATE matches 0 rows, enroll must 400 (not 200).

    Every upstream gate passes (valid hex/lengths, a genuine self-sig that
    verifies against the on-file Ed25519). Only the final ``set_user_x25519``
    UPDATE matches no row — modelling a race with account deletion. The
    handler must NOT falsely report ``enrolled``; it folds into the generic
    400, closing the latent fail-open.
    """
    kc = await make_keyed_client()

    # Force the persist to report "no row updated" without touching the DB.
    def _no_row(*_a, **_k) -> bool:
        return False

    monkeypatch.setattr(app.db, "set_user_x25519", _no_row)

    resp = await _enroll(kc.authed, kc.keystore, kc.username)
    assert resp.status_code == 400
    assert (await resp.get_json()) == {"error": "Invalid request"}


# ──────────────────────── directory uniformity ────────────────────────


async def test_directory_uniform_shape_and_length(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    make_user: Callable[..., str],
    fast_directory: None,
):
    """Unknown vs keyless vs enrolled all return 200, same KEYS and same
    body BYTE-LENGTH — no enumeration via shape or length.
    """
    enrolled = await make_keyed_client()
    r = await _enroll(enrolled.authed, enrolled.keystore, enrolled.username)
    assert r.status_code == 200

    # A user who exists but never enrolled X25519 (has an Ed25519 key).
    make_user(username="keyless", password="pw", ed25519_pubkey=b"\x09" * 32)

    authed = enrolled.authed
    resp_unknown = await authed.get("/api/users/ghost-user/pubkeys")
    resp_keyless = await authed.get("/api/users/keyless/pubkeys")
    resp_enrolled = await authed.get(f"/api/users/{enrolled.username}/pubkeys")

    for resp in (resp_unknown, resp_keyless, resp_enrolled):
        assert resp.status_code == 200

    body_unknown = await resp_unknown.get_json()
    body_keyless = await resp_keyless.get_json()
    body_enrolled = await resp_enrolled.get_json()

    # Identical key SET across all three (jsonify serializes keys sorted,
    # so order is identical too — the property that matters is that no
    # field is present/absent for one case but not another).
    expected_keys = {"ed25519", "x25519", "self_sig"}
    assert (
        set(body_unknown.keys())
        == set(body_keyless.keys())
        == set(body_enrolled.keys())
        == expected_keys
    )
    assert list(body_unknown.keys()) == list(body_enrolled.keys())
    # Every field is the same fixed hex width across all three.
    for body in (body_unknown, body_keyless, body_enrolled):
        assert len(body["ed25519"]) == 64
        assert len(body["x25519"]) == 64
        assert len(body["self_sig"]) == 128

    # Raw serialized byte-length is identical (the actual on-wire size).
    len_unknown = len(await resp_unknown.get_data())
    len_keyless = len(await resp_keyless.get_data())
    len_enrolled = len(await resp_enrolled.get_data())
    assert len_unknown == len_keyless == len_enrolled

    # The unknown / keyless cases must NOT leak a usable key.
    assert int(body_unknown["x25519"], 16) == 0
    assert int(body_keyless["x25519"], 16) == 0
    # Keyless still has its Ed25519 — but the unknown user does not.
    assert int(body_unknown["ed25519"], 16) == 0
    assert bytes.fromhex(body_keyless["ed25519"]) == b"\x09" * 32
    # An enrolled user DOES surface a non-zero key.
    assert int(body_enrolled["x25519"], 16) != 0


async def test_directory_applies_constant_deadline(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    monkeypatch: pytest.MonkeyPatch,
):
    """The lookup honors a constant-deadline floor (timing envelope).

    Patch the budget to a small but non-trivial value and assert BOTH the
    enrolled and the unknown lookups take at least that long — so a fast
    'no row' path cannot finish measurably sooner than a 'row exists' one.
    """
    floor = 0.05
    monkeypatch.setattr(users_mod, "_DIRECTORY_TIMING_BUDGET_S", floor)
    enrolled = await make_keyed_client()
    await _enroll(enrolled.authed, enrolled.keystore, enrolled.username)

    t0 = time.monotonic()
    await enrolled.authed.get(f"/api/users/{enrolled.username}/pubkeys")
    dt_enrolled = time.monotonic() - t0

    t0 = time.monotonic()
    await enrolled.authed.get("/api/users/ghost-user/pubkeys")
    dt_unknown = time.monotonic() - t0

    # Both meet the floor (allow a small scheduler slack below it).
    assert dt_enrolled >= floor - 0.01
    assert dt_unknown >= floor - 0.01


async def test_directory_canonicalizes_username(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    fast_directory: None,
):
    """A confusable/uppercase username resolves to the canonical row."""
    enrolled = await make_keyed_client(username="alice")
    await _enroll(enrolled.authed, enrolled.keystore, "alice")

    # Fullwidth ＡＬＩＣＥ canonicalizes to "alice".
    resp = await enrolled.authed.get("/api/users/ＡＬＩＣＥ/pubkeys")
    assert resp.status_code == 200
    body = await resp.get_json()
    assert bytes.fromhex(body["x25519"]) == enrolled.keystore.x25519_public_key()  # type: ignore[attr-defined]


# ──────────────────────────── /enrolled list ────────────────────────────


async def test_enrolled_lists_only_enrolled_users(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    make_user: Callable[..., str],
    fast_directory: None,
):
    """/enrolled returns enrolled users only; keyless users are excluded."""
    a = await make_keyed_client(username="enrolleda")
    b = await make_keyed_client(username="enrolledb")
    await _enroll(a.authed, a.keystore, "enrolleda")
    await _enroll(b.authed, b.keystore, "enrolledb")
    # A keyless user must NOT appear.
    make_user(username="keylessx", password="pw", ed25519_pubkey=b"\x05" * 32)

    resp = await a.authed.get("/api/users/enrolled")
    assert resp.status_code == 200
    body = await resp.get_json()
    names = {u["username"] for u in body["users"]}
    assert {"enrolleda", "enrolledb"} <= names
    assert "keylessx" not in names
    assert body["limit"] == 50 and body["offset"] == 0
    # Every listed entry carries a verifiable triple.
    from client.keymgmt import verify_x25519_self_sig

    for u in body["users"]:
        assert verify_x25519_self_sig(
            bytes.fromhex(u["ed25519"]),
            bytes.fromhex(u["x25519"]),
            bytes.fromhex(u["self_sig"]),
            u["username"],
        )


async def test_enrolled_pagination_bounds(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    fast_directory: None,
):
    """limit/offset are bounded (max 200) and slicing works."""
    kc = await make_keyed_client()
    await _enroll(kc.authed, kc.keystore, kc.username)

    # Over-max limit rejected.
    resp = await kc.authed.get("/api/users/enrolled?limit=201")
    assert resp.status_code == 400
    # Negative offset rejected.
    resp = await kc.authed.get("/api/users/enrolled?offset=-1")
    assert resp.status_code == 400
    # Non-int rejected.
    resp = await kc.authed.get("/api/users/enrolled?limit=abc")
    assert resp.status_code == 400
    # offset past the end yields an empty page (still 200).
    resp = await kc.authed.get("/api/users/enrolled?offset=1000")
    assert resp.status_code == 200
    assert (await resp.get_json())["users"] == []


async def test_directory_endpoints_require_auth(client):
    """All three directory routes reject an unauthenticated caller."""
    from tests.conftest import TEST_PEER_PORT

    scope = {"client": ("10.0.0.2", TEST_PEER_PORT)}
    r1 = await client.get("/api/users/alice/pubkeys", scope_base=scope)
    r2 = await client.get("/api/users/enrolled", scope_base=scope)
    r3 = await client.post(
        "/api/users/enroll_x25519",
        json={"x25519_pubkey": "11" * 32, "self_sig": "00" * 64},
        scope_base=scope,
    )
    assert r1.status_code == 401
    assert r2.status_code == 401
    assert r3.status_code == 401
