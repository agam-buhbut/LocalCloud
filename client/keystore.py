# LocalCloud - Client Key Store
#
# Python wrapper around the Rust keycore native module.
# All actual key operations are delegated to Rust — Python never
# sees raw private keys. This module handles:
# - Key file I/O (reading/writing encrypted key bundles)
# - Auto-lock on inactivity
# - Public key access

from __future__ import annotations

import contextlib
import os
import threading
import time
from pathlib import Path

import keycore


class KeyStore:
    """Client-side identity key management.

    Wraps the Rust `keycore.KeyPair` class. Private keys are stored
    exclusively in Rust memory (mlock'd, zeroize-on-drop).

    Concurrency: every operation that reads or mutates ``self._keypair``
    takes ``self._lock``. The lock is reentrant so the auto-lock timer
    can fire on the same thread mid-operation without deadlocking.
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
        # Reentrant so a single thread doing sign() → _touch_activity()
        # → _cancel_timer() doesn't deadlock if anything in that chain
        # re-acquires the lock.
        self._lock = threading.RLock()
        self._timer: threading.Timer | None = None

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

        with self._lock:
            kp = keycore.KeyPair.generate()
            encrypted = kp.encrypt_to_store(password.encode())

            # Write atomically with secure mode applied AT creation time —
            # `os.open` with O_EXCL|O_NOFOLLOW + explicit mode 0o600 avoids
            # the chmod-after-write race window where the file is briefly
            # world-readable.
            self.key_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp_path = self.key_file.with_suffix(".tmp")
            try:
                fd = os.open(
                    str(tmp_path),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                with os.fdopen(fd, "wb") as f:
                    f.write(encrypted)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(str(tmp_path), str(self.key_file))
            except Exception:
                if tmp_path.exists():
                    with contextlib.suppress(OSError):
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

        with self._lock:
            # Bound the read size via a single fd-bound syscall —
            # `stat()` + `read_bytes()` is TOCTOU. Same approach as
            # shared.io.read_capped used in the CLI. (Round-6 M)
            from shared.io import read_capped

            _MAX_STORE_BYTES = 16 * 1024
            try:
                data = read_capped(self.key_file, _MAX_STORE_BYTES)
            except (ValueError, OSError) as e:
                raise ValueError("Failed to read key store") from e
            try:
                self._keypair = keycore.KeyPair.decrypt_from_store(
                    data, password.encode()
                )
            except Exception as e:
                # Chain the original exception so a low-level
                # corruption error survives in __cause__ for debugging
                # — but the user-visible message stays generic so we
                # don't leak whether the failure was a wrong password
                # or a corrupted file. (#F8)
                raise ValueError("Failed to unlock key store") from e
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
        with self._lock:
            self._require_unlocked()
            assert self._keypair is not None
            result = bytes(self._keypair.x25519_public_key())
            self._touch_activity()
            return result

    def ed25519_public_key(self) -> bytes:
        """Get the Ed25519 public key (32 bytes)."""
        with self._lock:
            self._require_unlocked()
            assert self._keypair is not None
            result = bytes(self._keypair.ed25519_public_key())
            self._touch_activity()
            return result

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the Ed25519 private key.

        The private key never leaves Rust memory.
        """
        with self._lock:
            self._require_unlocked()
            assert self._keypair is not None
            result = bytes(self._keypair.sign(message))
            self._touch_activity()
            return result

    def wrap_file_keys(
        self,
        file_key: bytes,
        meta_key: bytes,
        file_id: bytes,
        recipient_pubkey: bytes,
    ) -> bytes:
        """Wrap file keys for a recipient.

        Performs ephemeral-static X25519 ECDH → HKDF → AEAD in Rust.
        `recipient_pubkey` is the recipient's X25519 public key.
        """
        # Belt-and-braces length check at the Python boundary mirroring
        # the Rust-side enforcement. A wrong-length value here would
        # otherwise raise a confusing PyValueError from Rust at call
        # time. (Round-2 LOW-7)
        if len(file_id) != 16:
            raise ValueError("file_id must be 16 bytes")
        if len(file_key) != 32 or len(meta_key) != 32:
            raise ValueError("file_key and meta_key must be 32 bytes")
        if len(recipient_pubkey) != 32:
            raise ValueError("recipient_pubkey must be 32 bytes")
        with self._lock:
            self._require_unlocked()
            assert self._keypair is not None
            result = bytes(
                self._keypair.wrap_file_keys(
                    file_key, meta_key, file_id, recipient_pubkey
                )
            )
            self._touch_activity()
            return result

    def unwrap_file_keys(
        self,
        wrapped_bundle: bytes,
        file_id: bytes,
        sender_pubkey: bytes,
    ) -> tuple[bytes, bytes]:
        """Unwrap file keys from a wrapped bundle.

        `sender_pubkey` is the sender's long-term Ed25519 identity public key
        (used as a domain binding, not for ECDH). The ephemeral X25519 public
        key used for ECDH is read from the bundle itself.

        Returns (file_key, meta_key).
        """
        if len(file_id) != 16:
            raise ValueError("file_id must be 16 bytes")
        if len(sender_pubkey) != 32:
            raise ValueError("sender_pubkey must be 32 bytes")
        with self._lock:
            self._require_unlocked()
            assert self._keypair is not None
            fk, mk = self._keypair.unwrap_file_keys(
                wrapped_bundle, file_id, sender_pubkey
            )
            self._touch_activity()
            return bytes(fk), bytes(mk)

    # ──────────── Internal ────────────

    def _require_unlocked(self) -> None:
        """Raise if keys are not currently unlocked."""
        if self._keypair is None:
            raise RuntimeError("Key store is locked. Call unlock() first.")

    def _touch_activity(self) -> None:
        """Update last activity time and reset auto-lock timer."""
        self._last_activity = time.time()
        self._cancel_timer()
        self._timer = threading.Timer(self.inactivity_timeout, self._auto_lock)
        self._timer.daemon = True
        self._timer.start()

    def _auto_lock(self) -> None:
        """Auto-lock keys after inactivity timeout.

        Re-checks ``_last_activity`` under the lock; otherwise a recent
        ``_touch_activity`` racing the timer fire could lock keys that
        the user just used. (#F30)
        """
        with self._lock:
            if (
                self._keypair is not None
                and time.time() - self._last_activity >= self.inactivity_timeout
            ):
                self._keypair = None  # Rust Drop → zeroize + munlock
                self._cancel_timer()

    def _cancel_timer(self) -> None:
        """Cancel the auto-lock timer. Caller must hold ``self._lock``."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
