"""Coverage for the real client HTTP layer (client/api_client.py).

The status-code -> exception mapping and response parsing previously shipped
entirely untested behind FakeCloudClient. These exercise the real CloudClient
against httpx.MockTransport (no network) and the mappers directly.
"""

from __future__ import annotations

import json
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


# ── request shape + response parse, per endpoint (CLIENT-1) ──


def _capture(client: CloudClient, response: httpx.Response) -> dict:
    """Mock the transport with a fixed ``response`` and capture the request.

    Returns a dict that is populated (method/path/params/content) when the
    client actually issues the request, so a test can assert the wire shape.
    """
    captured: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["method"] = req.method
        captured["path"] = req.url.path
        captured["params"] = dict(req.url.params)
        captured["content"] = req.content
        return response

    _mock(client, handler)
    return captured


def test_upload_init_request_and_parse(client: CloudClient) -> None:
    cap = _capture(client, httpx.Response(200, json={"upload_id": "u1"}))
    assert client.upload_init("photo.png", 3) == "u1"
    assert cap["method"] == "POST"
    assert cap["path"] == "/api/files/upload/init"
    body = json.loads(cap["content"])
    assert body == {"filename": "photo.png", "expected_chunks": 3}


def test_upload_init_malformed_response_raises(client: CloudClient) -> None:
    # ERR-2: a 200 with no upload_id is hostile/malformed → typed error.
    _mock(client, lambda req: httpx.Response(200, json={}))
    with pytest.raises(StorageError, match="upload_init"):
        client.upload_init("f", 1)


def test_upload_chunk_sends_octet_stream_and_parses_hash(client: CloudClient) -> None:
    cap = _capture(client, httpx.Response(200, json={"chunk_hash": "deadbeef"}))
    assert client.upload_chunk("u1", 2, b"\x09\x08\x07") == "deadbeef"
    assert cap["method"] == "POST"
    assert cap["path"] == "/api/files/upload/u1/chunk/2"
    assert cap["content"] == b"\x09\x08\x07"


def test_upload_chunk_malformed_response_raises(client: CloudClient) -> None:
    _mock(client, lambda req: httpx.Response(200, json={}))
    with pytest.raises(StorageError, match="upload_chunk"):
        client.upload_chunk("u1", 0, b"x")


def test_upload_finalize_request_and_parse(client: CloudClient) -> None:
    cap = _capture(client, httpx.Response(200, json={"file_id": "fid-1"}))
    out = client.upload_finalize(
        upload_id="u1",
        file_id="fid-1",
        total_chunks=2,
        file_header=b"\xaa\xbb",
        encrypted_metadata=b"\xcc\xdd",
        visibility=1,
        expected_hashes=["h0", "h1"],
    )
    assert out == "fid-1"
    assert cap["path"] == "/api/files/upload/u1/finalize"
    body = json.loads(cap["content"])
    # Binary blobs are hex-encoded on the wire.
    assert body["file_header"] == "aabb"
    assert body["encrypted_metadata"] == "ccdd"
    assert body["expected_hashes"] == ["h0", "h1"]
    assert body["visibility"] == 1


def test_list_files_request_params_and_parse(client: CloudClient) -> None:
    cap = _capture(client, httpx.Response(200, json={"files": [{"file_id": "a"}]}))
    files = client.list_files(limit=10, offset=5)
    assert files == [{"file_id": "a"}]
    assert cap["method"] == "GET"
    assert cap["path"] == "/api/files"
    assert cap["params"] == {"limit": "10", "offset": "5"}


def test_list_files_malformed_response_raises(client: CloudClient) -> None:
    # ERR-2: a 200 with no "files" list must surface as a typed error.
    _mock(client, lambda req: httpx.Response(200, json={"unexpected": True}))
    with pytest.raises(StorageError, match="file list"):
        client.list_files()


def test_delete_file_issues_delete(client: CloudClient) -> None:
    cap = _capture(client, httpx.Response(200, json={}))
    client.delete_file("ab" * 16)  # no raise
    assert cap["method"] == "DELETE"
    assert cap["path"] == f"/api/files/{'ab' * 16}"


def test_delete_file_maps_4xx(client: CloudClient) -> None:
    _mock(client, lambda req: httpx.Response(404, json={"error": "missing"}))
    with pytest.raises(StorageError, match="missing"):
        client.delete_file("ab" * 16)


def test_get_quota_returns_dict(client: CloudClient) -> None:
    quota = {"used_bytes": 1, "available_bytes": 2, "quota_bytes": 3}
    _mock(client, lambda req: httpx.Response(200, json=quota))
    assert client.get_quota() == quota


def test_get_file_metadata_returns_dict(client: CloudClient) -> None:
    meta = {"file_header": "00", "encrypted_metadata": "11", "total_chunks": 1}
    cap = _capture(client, httpx.Response(200, json=meta))
    assert client.get_file_metadata("ab" * 16) == meta
    assert cap["path"] == f"/api/files/{'ab' * 16}"


def test_share_file_request_shape(client: CloudClient) -> None:
    cap = _capture(client, httpx.Response(200, json={}))
    client.share_file("ab" * 16, "bob", b"\x01\x02")  # no raise
    assert cap["method"] == "POST"
    assert cap["path"] == f"/api/files/{'ab' * 16}/share"
    body = json.loads(cap["content"])
    assert body == {"shared_with": "bob", "wrapped_keys": "0102"}


def test_post_self_keys_request_shape(client: CloudClient) -> None:
    cap = _capture(client, httpx.Response(200, json={}))
    client.post_self_keys("ab" * 16, b"\xde\xad")  # no raise
    assert cap["path"] == f"/api/files/{'ab' * 16}/self_keys"
    assert json.loads(cap["content"]) == {"wrapped_keys": "dead"}


def test_unshare_file_issues_delete(client: CloudClient) -> None:
    cap = _capture(client, httpx.Response(200, json={}))
    client.unshare_file("ab" * 16, "bob")  # no raise
    assert cap["method"] == "DELETE"
    assert cap["path"] == f"/api/files/{'ab' * 16}/share/bob"


def test_get_wrapped_keys_hex_to_bytes(client: CloudClient) -> None:
    _mock(client, lambda req: httpx.Response(200, json={"wrapped_keys": "0a0b"}))
    assert client.get_wrapped_keys("ab" * 16) == b"\x0a\x0b"


def test_get_wrapped_keys_absent_is_none(client: CloudClient) -> None:
    _mock(client, lambda req: httpx.Response(200, json={}))
    assert client.get_wrapped_keys("ab" * 16) is None


def test_get_pubkeys_normalizes_all_zero_to_empty(client: CloudClient) -> None:
    # x25519 is present, ed25519 is the all-zero "absent" sentinel.
    resp = {
        "ed25519": "00" * 32,
        "x25519": "11" * 32,
        "self_sig": "",
    }
    _mock(client, lambda req: httpx.Response(200, json=resp))
    out = client.get_pubkeys("alice")
    assert out["ed25519"] == b""  # all-zero normalized to empty
    assert out["x25519"] == b"\x11" * 32
    assert out["self_sig"] == b""


def test_get_pubkeys_bad_hex_raises(client: CloudClient) -> None:
    _mock(client, lambda req: httpx.Response(200, json={"ed25519": "zz"}))
    with pytest.raises(StorageError, match="ed25519"):
        client.get_pubkeys("alice")


def test_get_enrolled_returns_users(client: CloudClient) -> None:
    cap = _capture(client, httpx.Response(200, json={"users": [{"username": "a"}]}))
    users = client.get_enrolled(limit=5, offset=0)
    assert users == [{"username": "a"}]
    assert cap["path"] == "/api/users/enrolled"
    assert cap["params"] == {"limit": "5", "offset": "0"}


def test_get_enrolled_malformed_response_raises(client: CloudClient) -> None:
    _mock(client, lambda req: httpx.Response(200, json={}))
    with pytest.raises(StorageError, match="enrolled"):
        client.get_enrolled()


def test_login_missing_token_raises(client: CloudClient) -> None:
    _mock(client, lambda req: httpx.Response(200, json={"not_token": "x"}))
    with pytest.raises(AuthError, match="no session token"):
        client.login("alice", "pw")
