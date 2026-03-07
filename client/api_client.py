# LocalCloud - Client API Module
#
# HTTP client for communicating with the LocalCloud server.
# All requests go through WireGuard and include session tokens.

from __future__ import annotations

from typing import Optional

import httpx

from shared.exceptions import AuthError, StorageError, UploadError


class CloudClient:
    """HTTP client for the LocalCloud server API."""

    def __init__(
        self,
        server_url: str = "http://10.0.0.1:8443",
        timeout: float = 30.0,
    ):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self._token: Optional[str] = None
        self._client = httpx.Client(timeout=timeout)

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

        #14: Safely handles non-JSON responses.
        """
        if resp.status_code == 401:
            raise AuthError("Authentication required")
        if resp.status_code == 429:
            raise AuthError("Rate limited")
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": resp.text or "Request failed"}
            raise StorageError(body.get("error", "Request failed"))
        try:
            return resp.json()
        except Exception:
            raise StorageError("Invalid server response")

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
        self._token = data["token"]
        return self._token

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

    def upload_chunk(
        self, upload_id: str, chunk_index: int, chunk_data: bytes
    ) -> str:
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

    def upload_file(
        self,
        filename: str,
        chunks: list[bytes],
        file_id: str,
        file_header: bytes,
        encrypted_metadata: bytes,
        visibility: int = 0,
    ) -> str:
        """Complete upload flow: init → chunks → finalize."""
        upload_id = self.upload_init(filename, len(chunks))

        hash_strings = []
        for i, chunk in enumerate(chunks):
            server_hash = self.upload_chunk(upload_id, i, chunk)
            hash_strings.append(server_hash)

        return self.upload_finalize(
            upload_id=upload_id,
            file_id=file_id,
            total_chunks=len(chunks),
            file_header=file_header,
            encrypted_metadata=encrypted_metadata,
            visibility=visibility,
            expected_hashes=hash_strings,
        )

    # ──────────────────────────── Download ────────────────────────────

    def get_file_metadata(self, file_id: str) -> dict:
        """Get file metadata (header + encrypted metadata)."""
        resp = self._client.get(
            f"{self.server_url}/api/files/{file_id}",
            headers=self._headers(),
        )
        return self._check_response(resp)

    def download_chunk(self, file_id: str, chunk_index: int) -> bytes:
        """Download a single encrypted chunk."""
        resp = self._client.get(
            f"{self.server_url}/api/files/{file_id}/chunk/{chunk_index}",
            headers={
                "Authorization": f"Bearer {self._token}",
            },
        )
        if resp.status_code != 200:
            raise StorageError("Download failed")
        return resp.content

    def download_file(self, file_id: str) -> tuple[dict, list[bytes]]:
        """Download a complete file (metadata + all chunks).

        Returns (metadata_dict, list_of_chunk_bytes).
        """
        metadata = self.get_file_metadata(file_id)
        total_chunks = metadata["total_chunks"]

        chunks = []
        for i in range(total_chunks):
            chunk = self.download_chunk(file_id, i)
            chunks.append(chunk)

        return metadata, chunks

    # ──────────────────────────── File Management ────────────────────────────

    def list_files(self) -> list[dict]:
        """List all accessible files."""
        resp = self._client.get(
            f"{self.server_url}/api/files",
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

    def share_file(
        self, file_id: str, username: str, wrapped_keys: bytes
    ) -> None:
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

    def get_wrapped_keys(self, file_id: str) -> Optional[bytes]:
        """Get wrapped keys for a shared file."""
        resp = self._client.get(
            f"{self.server_url}/api/files/{file_id}/wrapped_keys",
            headers=self._headers(),
        )
        data = self._check_response(resp)
        wk = data.get("wrapped_keys")
        return bytes.fromhex(wk) if wk else None
