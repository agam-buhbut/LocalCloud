# LocalCloud - Client API Module
#
# HTTP client for communicating with the LocalCloud server.
# All requests go through WireGuard and include session tokens.

from __future__ import annotations

import json
from collections.abc import Iterator

import httpx

from shared.exceptions import AuthError, StorageError


class CloudClient:
    """HTTP client for the LocalCloud server API."""

    def __init__(
        self,
        server_url: str = "http://10.0.0.1:8443",
        timeout: float = 30.0,
    ):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self._token: str | None = None
        # Bound the connection pool so chunk uploads share keepalive
        # connections instead of opening a fresh TCP socket per chunk.
        self._client = httpx.Client(
            timeout=timeout,
            limits=httpx.Limits(
                max_keepalive_connections=8,
                max_connections=16,
            ),
        )

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    @property
    def is_authenticated(self) -> bool:
        return self._token is not None

    def _headers(self) -> dict:
        """Build request headers with auth token."""
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _check_response(self, resp: httpx.Response) -> dict:
        """Check response status and return JSON body.

        Narrow exception handlers; full chain of cause via ``raise from``
        so the original transport failure isn't lost.
        """
        if resp.status_code == 401:
            raise AuthError("Authentication required")
        if resp.status_code == 429:
            raise AuthError("Rate limited")
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except (json.JSONDecodeError, ValueError):
                body = {"error": resp.text or "Request failed"}
            raise StorageError(body.get("error", "Request failed"))
        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError) as e:
            raise StorageError("Invalid server response") from e

    def _check_binary_response(self, resp: httpx.Response) -> bytes:
        """Like _check_response but for endpoints returning raw bytes.

        Maps 4xx/5xx to typed exceptions; on success, returns the body
        without forcing a JSON decode.
        """
        if resp.status_code == 401:
            raise AuthError("Authentication required")
        if resp.status_code == 429:
            raise AuthError("Rate limited")
        if resp.status_code >= 400:
            try:
                body = resp.json()
                msg = body.get("error", "Request failed")
            except (json.JSONDecodeError, ValueError):
                msg = resp.text or f"HTTP {resp.status_code}"
            raise StorageError(msg)
        if resp.status_code != 200:
            raise StorageError(f"Unexpected status {resp.status_code}")
        return resp.content

    # ──────────────────────────── Auth ────────────────────────────

    def login(self, username: str, password: str) -> str:
        """Authenticate and store session token.

        Returns the session token.
        """
        resp = self._client.post(
            f"{self.server_url}/api/auth/login",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"},
        )
        data = self._check_response(resp)
        token = data.get("token")
        if not isinstance(token, str) or not token:
            raise AuthError("Server returned no session token")
        self._token = token
        return token

    # ──────────────────────────── Upload ────────────────────────────

    def upload_init(self, filename: str, expected_chunks: int) -> str:
        """Initialize an upload session. Returns upload_id."""
        resp = self._client.post(
            f"{self.server_url}/api/files/upload/init",
            json={
                "filename": filename,
                "expected_chunks": expected_chunks,
            },
            headers=self._headers(),
        )
        data = self._check_response(resp)
        return data["upload_id"]

    def upload_chunk(self, upload_id: str, chunk_index: int, chunk_data: bytes) -> str:
        """Upload a single encrypted chunk. Returns chunk hash."""
        resp = self._client.post(
            f"{self.server_url}/api/files/upload/{upload_id}/chunk/{chunk_index}",
            content=chunk_data,
            headers={
                "Content-Type": "application/octet-stream",
                "Authorization": f"Bearer {self._token}",
            },
        )
        data = self._check_response(resp)
        return data["chunk_hash"]

    def upload_finalize(
        self,
        upload_id: str,
        file_id: str,
        total_chunks: int,
        file_header: bytes,
        encrypted_metadata: bytes,
        visibility: int = 0,
        expected_hashes: list[str] | None = None,
    ) -> str:
        """Finalize an upload. Returns file_id."""
        payload = {
            "file_id": file_id,
            "total_chunks": total_chunks,
            "file_header": file_header.hex(),
            "encrypted_metadata": encrypted_metadata.hex(),
            "visibility": visibility,
        }
        if expected_hashes:
            payload["expected_hashes"] = expected_hashes

        resp = self._client.post(
            f"{self.server_url}/api/files/upload/{upload_id}/finalize",
            json=payload,
            headers=self._headers(),
        )
        data = self._check_response(resp)
        return data["file_id"]

    def set_token(self, token: str) -> None:
        """Set the session token (e.g. loaded from file)."""
        self._token = token

    # ──────────────────────────── Download ────────────────────────────

    def get_file_metadata(self, file_id: str) -> dict:
        """Get file metadata (header + encrypted metadata)."""
        resp = self._client.get(
            f"{self.server_url}/api/files/{file_id}",
            headers=self._headers(),
        )
        return self._check_response(resp)

    def get_owner_pubkey(self, file_id: str) -> bytes | None:
        """Fetch the file owner's Ed25519 identity public key.

        Returns the raw 32-byte pubkey, or None if the server has no
        registered key for the owner. Raises StorageError on 4xx/5xx.
        """
        resp = self._client.get(
            f"{self.server_url}/api/files/{file_id}/owner_pubkey",
            headers=self._headers(),
        )
        data = self._check_response(resp)
        pk = data.get("pubkey")
        if not isinstance(pk, str) or not pk:
            return None
        try:
            return bytes.fromhex(pk)
        except ValueError as e:
            raise StorageError("Invalid owner_pubkey response") from e

    def download_chunk(self, file_id: str, chunk_index: int) -> bytes:
        """Download a single encrypted chunk.

        Surfaces 4xx/5xx as typed errors with the server's message
        when available, rather than swallowing them as a generic
        "Download failed".
        """
        resp = self._client.get(
            f"{self.server_url}/api/files/{file_id}/chunk/{chunk_index}",
            headers={
                "Authorization": f"Bearer {self._token}",
            },
        )
        return self._check_binary_response(resp)

    def iter_chunks(self, file_id: str, total_chunks: int) -> Iterator[bytes]:
        """Yield each encrypted chunk in order.

        Generator-shaped so callers can pipe directly into a streaming
        decrypter without ever materializing the full file in RAM.
        """
        for i in range(total_chunks):
            yield self.download_chunk(file_id, i)

    # ──────────────────────────── File Management ────────────────────────────

    def list_files(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """List accessible files with pagination."""
        resp = self._client.get(
            f"{self.server_url}/api/files",
            params={"limit": limit, "offset": offset},
            headers=self._headers(),
        )
        data = self._check_response(resp)
        return data["files"]

    def delete_file(self, file_id: str) -> None:
        """Delete a file."""
        resp = self._client.delete(
            f"{self.server_url}/api/files/{file_id}",
            headers=self._headers(),
        )
        self._check_response(resp)

    def get_quota(self) -> dict:
        """Get quota information."""
        resp = self._client.get(
            f"{self.server_url}/api/files/quota",
            headers=self._headers(),
        )
        return self._check_response(resp)

    # ──────────────────────────── Sharing ────────────────────────────

    def share_file(self, file_id: str, username: str, wrapped_keys: bytes) -> None:
        """Share a file with another user."""
        resp = self._client.post(
            f"{self.server_url}/api/files/{file_id}/share",
            json={
                "shared_with": username,
                "wrapped_keys": wrapped_keys.hex(),
            },
            headers=self._headers(),
        )
        self._check_response(resp)

    def unshare_file(self, file_id: str, username: str) -> None:
        """Revoke a previously-granted share for a recipient.

        Server-side revocation only — recipients who already downloaded
        the wrapped keys still have them offline. To fully revoke the
        owner must re-encrypt under a new file_key. (Round-3 M9)
        """
        resp = self._client.delete(
            f"{self.server_url}/api/files/{file_id}/share/{username}",
            headers=self._headers(),
        )
        self._check_response(resp)

    def get_wrapped_keys(self, file_id: str) -> bytes | None:
        """Get wrapped keys for a shared file."""
        resp = self._client.get(
            f"{self.server_url}/api/files/{file_id}/wrapped_keys",
            headers=self._headers(),
        )
        data = self._check_response(resp)
        wk = data.get("wrapped_keys")
        return bytes.fromhex(wk) if wk else None
