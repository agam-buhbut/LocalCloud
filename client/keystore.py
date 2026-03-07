# LocalCloud - Client Key Store
#
# Python wrapper around the Rust keycore native module.
# All actual key operations are delegated to Rust — Python never
# sees raw private keys. This module handles:
# - Key file I/O (reading/writing encrypted key bundles)
# - Auto-lock on inactivity
# - Public key access

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Optional


class KeyStore:
    """Client-side identity key management.

    Wraps the Rust `keycore.KeyPair` class. Private keys are stored
    exclusively in Rust memory (mlock'd, zeroize-on-drop).
    """

    def __init__(self, key_file: str | Path, inactivity_timeout: int = 300):
        """
        Args:
            key_file: Path to the encrypted key store file
            inactivity_timeout: Seconds of inactivity before auto-locking keys
        """
        self.key_file = Path(key_file)
        self.inactivity_timeout = inactivity_timeout
        self._keypair = None  # keycore.KeyPair or None
        self._last_activity: float = 0.0
        self._lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None

    @property
    def is_unlocked(self) -> bool:
        """Check if keys are currently unlocked in memory."""
        return self._keypair is not None

    @property
    def has_keys(self) -> bool:
        """Check if an encrypted key file exists on disk."""
        return self.key_file.exists()

    def generate(self, password: str) -> None:
        """Generate a new identity keypair and save encrypted to disk.

        Args:
            password: Password to encrypt the key bundle

        Raises:
            FileExistsError: If key file already exists
            RuntimeError: If key generation fails
        """
        if self.key_file.exists():
            raise FileExistsError(
                f"Key file already exists: {self.key_file}. "
                "Delete it first if you want to regenerate keys."
            )

        import keycore

        with self._lock:
            kp = keycore.KeyPair.generate()
            encrypted = kp.encrypt_to_store(password.encode())

            # Write atomically
            self.key_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp_path = self.key_file.with_suffix(".tmp")
            try:
                with open(tmp_path, "wb") as f:
                    f.write(encrypted)
                os.chmod(str(tmp_path), 0o600)
                os.rename(str(tmp_path), str(self.key_file))
            except Exception:
                if tmp_path.exists():
                    tmp_path.unlink()
                raise

            self._keypair = kp
            self._touch_activity()

    def unlock(self, password: str) -> None:
        """Unlock keys from the encrypted store file.

        Args:
            password: Password to decrypt the key bundle

        Raises:
            FileNotFoundError: If no key file exists
            ValueError: If password is wrong or data is corrupted
        """
        if not self.key_file.exists():
            raise FileNotFoundError(
                f"No key file found at: {self.key_file}. "
                "Run 'localcloud init' first."
            )

        import keycore

        with self._lock:
            data = self.key_file.read_bytes()
            try:
                self._keypair = keycore.KeyPair.decrypt_from_store(
                    data, password.encode()
                )
            except Exception:
                raise ValueError("Failed to unlock key store")
            self._touch_activity()

    def lock(self) -> None:
        """Lock keys — zeroize Rust memory and release mlock.

        After locking, the KeyPair is dropped (Rust Drop trait handles
        zeroization and munlock).
        """
        with self._lock:
            self._keypair = None  # Rust Drop → zeroize + munlock
            self._cancel_timer()

    def x25519_public_key(self) -> bytes:
        """Get the X25519 public key (32 bytes)."""
        self._require_unlocked()
        self._touch_activity()
        return bytes(self._keypair.x25519_public_key())

    def ed25519_public_key(self) -> bytes:
        """Get the Ed25519 public key (32 bytes)."""
        self._require_unlocked()
        self._touch_activity()
        return bytes(self._keypair.ed25519_public_key())

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the Ed25519 private key.

        The private key never leaves Rust memory.
        """
        self._require_unlocked()
        self._touch_activity()
        return bytes(self._keypair.sign(message))

    def wrap_file_keys(
        self,
        file_key: bytes,
        meta_key: bytes,
        file_id: bytes,
        recipient_pubkey: bytes,
    ) -> bytes:
        """Wrap file keys for a recipient.

        Performs X25519 ECDH → HKDF → AEAD in Rust.
        """
        self._require_unlocked()
        self._touch_activity()
        return bytes(
            self._keypair.wrap_file_keys(
                file_key, meta_key, file_id, recipient_pubkey
            )
        )

    def unwrap_file_keys(
        self,
        wrapped_bundle: bytes,
        file_id: bytes,
        sender_pubkey: bytes,
    ) -> tuple[bytes, bytes]:
        """Unwrap file keys from a wrapped bundle.

        Returns (file_key, meta_key).
        """
        self._require_unlocked()
        self._touch_activity()
        fk, mk = self._keypair.unwrap_file_keys(
            wrapped_bundle, file_id, sender_pubkey
        )
        return bytes(fk), bytes(mk)

    # ──────────── Internal ────────────

    def _require_unlocked(self) -> None:
        """Raise if keys are not currently unlocked."""
        if self._keypair is None:
            raise RuntimeError(
                "Key store is locked. Call unlock() first."
            )

    def _touch_activity(self) -> None:
        """Update last activity time and reset auto-lock timer."""
        self._last_activity = time.time()
        self._cancel_timer()
        self._timer = threading.Timer(
            self.inactivity_timeout, self._auto_lock
        )
        self._timer.daemon = True
        self._timer.start()

    def _auto_lock(self) -> None:
        """Auto-lock keys after inactivity timeout."""
        if time.time() - self._last_activity >= self.inactivity_timeout:
            self.lock()

    def _cancel_timer(self) -> None:
        """Cancel the auto-lock timer."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
