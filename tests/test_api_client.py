"""Coverage for the real client HTTP layer (client/api_client.py).

The status-code -> exception mapping and response parsing previously shipped
entirely untested behind FakeCloudClient. These exercise the real CloudClient
against httpx.MockTransport (no network) and the mappers directly.
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest

from client.api_client import CloudClient
from shared.exceptions import AuthError, StorageError


@pytest.fixture()
def client() -> Iterator[CloudClient]:
    c = CloudClient("http://server")
    try:
        yield c
    finally:
        c.close()


def _mock(client: CloudClient, handler) -> None:
    """Swap the client's transport for a deterministic mock."""
    client._client.close()  # close the real connection pool before replacing it
    client._client = httpx.Client(transport=httpx.MockTransport(handler))


# ── status -> exception mapping (_raise_for_status) ──


def test_401_maps_to_autherror(client: CloudClient) -> None:
    with pytest.raises(AuthError):
        client._raise_for_status(httpx.Response(401, json={"error": "no"}))


def test_429_maps_to_autherror(client: CloudClient) -> None:
    with pytest.raises(AuthError, match="Rate limited"):
        client._raise_for_status(httpx.Response(429))


def test_4xx_json_error_maps_to_storageerror(client: CloudClient) -> None:
    with pytest.raises(StorageError, match="boom"):
        client._raise_for_status(httpx.Response(400, json={"error": "boom"}))


def test_5xx_text_fallback_maps_to_storageerror(client: CloudClient) -> None:
    with pytest.raises(StorageError):
        client._raise_for_status(httpx.Response(503, text="upstream down"))


def test_2xx_is_noop(client: CloudClient) -> None:
    client._raise_for_status(httpx.Response(200, json={"ok": True}))  # no raise


def test_check_response_bad_json_raises(client: CloudClient) -> None:
    with pytest.raises(StorageError, match="Invalid server response"):
        client._check_response(httpx.Response(200, text="not json"))


def test_check_binary_non_200_raises(client: CloudClient) -> None:
    with pytest.raises(StorageError):
        client._check_binary_response(httpx.Response(204))


# ── endpoint round trips through the real call path (MockTransport) ──


def test_login_extracts_token(client: CloudClient) -> None:
    _mock(client, lambda req: httpx.Response(200, json={"token": "T0K"}))
    assert client.login("alice", "pw") == "T0K"


def test_get_owner_pubkey_parses_hex(client: CloudClient) -> None:
    pk = bytes(range(32))

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path.endswith("/owner_pubkey")
        return httpx.Response(200, json={"pubkey": pk.hex()})

    _mock(client, handler)
    assert client.get_owner_pubkey("ab" * 16) == pk


def test_get_owner_pubkey_absent_is_none(client: CloudClient) -> None:
    _mock(client, lambda req: httpx.Response(200, json={}))
    assert client.get_owner_pubkey("ab" * 16) is None


def test_get_owner_pubkey_bad_hex_raises(client: CloudClient) -> None:
    _mock(client, lambda req: httpx.Response(200, json={"pubkey": "zz"}))
    with pytest.raises(StorageError, match="Invalid owner_pubkey"):
        client.get_owner_pubkey("ab" * 16)


def test_get_owner_pubkey_wrong_length_raises(client: CloudClient) -> None:
    # Valid hex but not 32 bytes — must be rejected at the trust boundary.
    _mock(client, lambda req: httpx.Response(200, json={"pubkey": "abcd"}))
    with pytest.raises(StorageError, match="length"):
        client.get_owner_pubkey("ab" * 16)


def test_download_chunk_returns_bytes(client: CloudClient) -> None:
    _mock(client, lambda req: httpx.Response(200, content=b"\x00\x01\x02"))
    assert client.download_chunk("ab" * 16, 0) == b"\x00\x01\x02"
