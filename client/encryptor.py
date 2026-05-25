# LocalCloud - Client Per-File Encryption Engine
#
# Implements chunked, padded, authenticated encryption with Merkle tree
# integrity proofs and signed roots for replay protection.
#
# Security properties:
# - Per-file random keys (file_key, meta_key) from CSPRNG
# - Per-chunk unique nonce (192-bit random)
# - AEAD binding: file_id + chunk_index + version + total_chunks
# - Merkle root signed with Ed25519 to detect server rollback
# - Atomic failure: any verification error aborts entire operation
# - Streaming I/O: plaintext never fully materialised in RAM

from __future__ import annotations

import contextlib
import hmac
import math
import os
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import keycore

from client.keystore import KeyStore
from shared.crypto import (
    blake2b_hash,
    decrypt_chunk,
    encrypt_chunk,
    generate_key,
    generate_nonce,
    merkle_root,
)
from shared.exceptions import (
    CryptoError,
    DecryptionError,
    SignatureError,
)
from shared.models import (
    CHUNK_SIZE,
    MAX_CHUNKS_PER_FILE,
    MAX_METADATA_BYTES,
    NONCE_LEN,
    TAG_LEN,
    ChunkAAD,
    FileHeader,
    MetadataBlob,
    Visibility,
    build_merkle_signing_input,
    pad_to_size_class,
    unpad,
)


@dataclass
class EncryptResult:
    """Result of streaming encryption — header + metadata for upload.

    The encrypted chunks themselves are *not* held here; they are dispatched
    via the ``on_chunk`` callback during ``encrypt_file`` to keep memory
    usage bounded.
    """

    header: FileHeader
    chunk_hashes: list[bytes]  # BLAKE2b of each ciphertext chunk
    encrypted_metadata: bytes
    file_key: bytes  # For key wrapping (owner keeps this)
    meta_key: bytes  # For key wrapping (owner keeps this)


# Operational chunk-count ceiling. Imported from shared.models so the
# encryptor, server, and any future consumer share one source of truth
# (Round-2 LOW-1 / Round-3 fix). Each leaf hash is 32 bytes, so the
# in-RAM Merkle leaf list is bounded by MAX_CHUNKS_PER_FILE * 32 bytes
# (= ~3.2 MiB at 100k chunks).
MAX_CHUNKS: int = MAX_CHUNKS_PER_FILE


class FileEncryptor:
    """Per-file encryption engine.

    Each file gets independent random keys. Keys are never derived from
    filenames, timestamps, or user secrets. Encryption and decryption are
    fully streaming — plaintext is never fully materialised in RAM.
    """

    def __init__(self, keystore: KeyStore, chunk_size: int = CHUNK_SIZE):
        self.keystore = keystore
        self.chunk_size = chunk_size

    # ──────────────────────── Upload (streaming) ────────────────────────

    def encrypt_file(
        self,
        input_path: Path,
        filename: str,
        on_chunk: Callable[[int, bytes], None],
        visibility: Visibility = Visibility.PRIVATE,
        owner: str = "",
    ) -> EncryptResult:
        """Encrypt a file with per-file random keys, streaming chunk-by-chunk.

        Reads ``input_path`` in ``chunk_size`` increments, encrypts each
        chunk with a fresh nonce and bound AAD, and invokes ``on_chunk``
        with ``(index, encrypted_blob)`` so the caller can ship chunks
        upstream without buffering them all.

        Args:
            input_path: source file on disk
            filename: original filename (recorded in encrypted metadata)
            on_chunk: callback invoked for every encrypted chunk
            visibility: file visibility mode
            owner: owner username (recorded in encrypted metadata)

        Returns:
            EncryptResult with header + metadata + per-file keys
        """
        input_path = Path(input_path)
        original_size = input_path.stat().st_size

        # Pre-compute total_chunks so it can be bound into AAD up front.
        # Empty file still produces one padded chunk (matches previous
        # behaviour) for AEAD-tag-presence reasons.
        if original_size == 0:
            total_chunks = 1
        else:
            total_chunks = math.ceil(original_size / self.chunk_size)
        if total_chunks > MAX_CHUNKS:
            raise CryptoError(f"File exceeds maximum chunk count ({MAX_CHUNKS})")

        # Per-file random keys
        file_key = generate_key()
        meta_key = generate_key()
        file_id = os.urandom(16)

        chunk_hashes: list[bytes] = []

        # Stream-read source, encrypt each chunk, dispatch to caller
        with open(input_path, "rb") as src:
            for i in range(total_chunks):
                buf = src.read(self.chunk_size)
                # Pad last chunk (or sole chunk for an empty file) so all
                # ciphertext blocks have the same length on the wire.
                if len(buf) < self.chunk_size:
                    buf = buf + b"\x00" * (self.chunk_size - len(buf))

                nonce = generate_nonce()
                aad = ChunkAAD(
                    file_id=file_id,
                    chunk_index=i,
                    total_chunks=total_chunks,
                ).serialize()
                ciphertext = encrypt_chunk(file_key, nonce, buf, aad)
                chunk_blob = nonce + ciphertext

                chunk_hashes.append(blake2b_hash(chunk_blob))
                on_chunk(i, chunk_blob)

        # Build Merkle tree and sign a domain-separated input binding the
        # root to this file_id, chunk geometry, and protocol context —
        # prevents cross-context signature replay AND server-side header
        # field tampering. (Round-2 H3)
        root = merkle_root(chunk_hashes)
        from shared.models import PROTOCOL_VERSION

        signature = self.keystore.sign(
            build_merkle_signing_input(
                file_id,
                root,
                chunk_size=self.chunk_size,
                total_chunks=total_chunks,
                protocol_version=PROTOCOL_VERSION,
            )
        )

        header = FileHeader(
            file_id=file_id,
            chunk_size=self.chunk_size,
            total_chunks=total_chunks,
            merkle_root=root,
            signature=signature,
        )

        # Encrypt metadata
        now = time.time()
        metadata = MetadataBlob(
            owner=owner,
            visibility=visibility,
            created_at=now,
            modified_at=now,
            original_size=original_size,
            version_number=1,
        )
        meta_plain = metadata.serialize()
        meta_padded = pad_to_size_class(meta_plain)
        meta_nonce = generate_nonce()
        meta_aad = ChunkAAD(
            file_id=file_id,
            chunk_index=0xFFFFFFFF,  # Special index for metadata
            total_chunks=0,
        ).serialize()
        meta_ct = encrypt_chunk(meta_key, meta_nonce, meta_padded, meta_aad)
        encrypted_metadata = meta_nonce + meta_ct

        return EncryptResult(
            header=header,
            chunk_hashes=chunk_hashes,
            encrypted_metadata=encrypted_metadata,
            file_key=file_key,
            meta_key=meta_key,
        )

    # ──────────────────────── Download (streaming) ────────────────────────

    def decrypt_file(
        self,
        input_chunks: Iterator[bytes],
        header_data: bytes,
        encrypted_metadata: bytes,
        file_key: bytes,
        meta_key: bytes,
        signer_pubkey: bytes,
        output_path: Path,
    ) -> None:
        """Decrypt a file with full integrity verification, streaming to disk.

        Writes the plaintext to a temp file in the same directory as
        ``output_path`` with mode 0o600, then atomically renames into place.
        On *any* verification failure the temp file is removed before the
        exception propagates.

        Actual verification order:

        1. Parse + validate header
        2. Verify Ed25519 signature over the canonical signing input
           (file_id || merkle_root || chunk_size || total_chunks ||
            protocol_version) — fails before any chunk is touched
        3. AEAD-decrypt the metadata blob (under meta_key) — establishes
           that meta_key is correct and yields original_size for the
           last-chunk trim
        4. For each chunk: AEAD (Poly1305) tag verify *before* writing
           plaintext to the temp file
        5. After the last chunk: recompute Merkle root and constant-time
           compare against the signed value
        6. On ANY failure: delete temp file, raise — never expose
           unverified plaintext at ``output_path``

        Note: plaintext is written to a temp file as chunks arrive
        because each chunk's AAD already binds file_id + chunk_index
        + total_chunks. A hostile server cannot construct alternate
        valid AEAD chunks without ``file_key``; the Merkle root then
        catches rollback attacks. For strict "no plaintext until
        Merkle root verifies" semantics, the temp file lives in
        ``output_path.parent`` with mode 0o600 and is os.replace'd
        only after step 5 passes.

        Args:
            input_chunks: iterator yielding (nonce || ciphertext) blobs
            header_data: serialized FileHeader
            encrypted_metadata: nonce || ciphertext of metadata
            file_key: decrypted file encryption key
            meta_key: decrypted metadata encryption key
            signer_pubkey: Ed25519 public key of the file owner
            output_path: destination for decrypted plaintext

        Raises:
            SignatureError: Ed25519 signature invalid
            DecryptionError: AEAD tag verification fails, Merkle root
                mismatch, chunk count mismatch, or any other integrity
                failure (all integrity failures normalize to this class
                so a caller cannot distinguish which gate tripped)
            CryptoError: chunk count mismatch or chunk too large
        """
        # 1. Parse and validate header
        header = FileHeader.deserialize(header_data)
        header.validate()

        # 2. Verify Ed25519 signature on the domain-separated Merkle-root
        #    input *before* touching any chunk ciphertext. A bad signature
        #    means we treat the server's chunks as adversarial input.
        signing_input = build_merkle_signing_input(
            header.file_id,
            header.merkle_root,
            chunk_size=header.chunk_size,
            total_chunks=header.total_chunks,
            protocol_version=header.version,
        )
        try:
            ok = keycore.verify_signature(
                signer_pubkey, signing_input, header.signature
            )
        except ValueError as e:
            # Rust side raises PyValueError for malformed-length signatures
            # or pubkeys. Normalize to SignatureError so callers don't
            # see a different exception type for "bad bytes" vs "valid
            # bytes that don't verify".
            raise SignatureError("Invalid Merkle root signature") from e
        if not ok:
            raise SignatureError("Invalid Merkle root signature")

        # Decrypt metadata up front so original_size is known when we hit
        # the last (possibly padded) chunk — also fails fast on a wrong
        # meta_key.
        metadata = self.decrypt_metadata(encrypted_metadata, meta_key, header.file_id)
        original_size: int = metadata.original_size
        # Reject malformed original_size before we use it to slice the
        # last chunk. A hostile sender (file owner) could put a negative
        # value and silently truncate the recipient's output; we'd
        # rather fail loudly than produce wrong bytes.
        if original_size < 0 or original_size > header.total_chunks * header.chunk_size:
            raise DecryptionError("Metadata original_size out of range")

        # Bound per-chunk ciphertext length — server-supplied data:
        # length leak protection comes from chunk_size being fixed.
        max_chunk_blob = NONCE_LEN + header.chunk_size + TAG_LEN

        output_path = Path(output_path)
        output_dir = output_path.parent
        # Create a temp file in the same directory so os.replace is atomic
        # (cross-device renames would not be). Use O_EXCL|O_NOFOLLOW with
        # explicit mode 0o600 — no chmod race window.
        temp_path = output_dir / (f".lc-dl-{header.file_id.hex()}-{os.getpid()}.tmp")
        try:
            fd = os.open(
                str(temp_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError as e:
            raise CryptoError("Temporary download file already exists") from e

        chunk_hashes: list[bytes] = []
        bytes_written = 0
        try:
            with os.fdopen(fd, "wb") as out:
                idx = 0
                for chunk_blob in input_chunks:
                    if idx >= header.total_chunks:
                        # Normalize all integrity-related failures to
                        # DecryptionError so the caller sees one error
                        # class regardless of which gate tripped
                        # (chunk count, AEAD, Merkle). Distinguishing
                        # them at the API surface would let the server
                        # observe which internal check rejected.
                        raise DecryptionError("Chunk count mismatch")

                    # Length bound: reject obviously malformed chunks
                    # before performing AEAD work on them.
                    if len(chunk_blob) > max_chunk_blob:
                        raise DecryptionError("Chunk blob exceeds size bound")
                    if len(chunk_blob) < NONCE_LEN + TAG_LEN:
                        raise DecryptionError("Chunk too short")

                    nonce = chunk_blob[:NONCE_LEN]
                    ciphertext = chunk_blob[NONCE_LEN:]

                    aad = ChunkAAD(
                        file_id=header.file_id,
                        chunk_index=idx,
                        total_chunks=header.total_chunks,
                    ).serialize()

                    # AEAD verifies the tag before yielding plaintext —
                    # if it fails, nothing is written for this chunk.
                    try:
                        plaintext_chunk = decrypt_chunk(
                            file_key, nonce, ciphertext, aad
                        )
                    except DecryptionError:
                        raise
                    except Exception as e:
                        raise DecryptionError("Chunk decryption failed") from e

                    chunk_hashes.append(blake2b_hash(chunk_blob))

                    # Trim padding on the final chunk according to
                    # original_size from the verified metadata.
                    remaining = original_size - bytes_written
                    if idx == header.total_chunks - 1 and original_size > 0:
                        if remaining < len(plaintext_chunk):
                            plaintext_chunk = plaintext_chunk[:remaining]
                    elif original_size == 0:
                        # Empty file — discard all plaintext (one padded
                        # chunk was produced at encrypt time).
                        plaintext_chunk = b""

                    out.write(plaintext_chunk)
                    bytes_written += len(plaintext_chunk)
                    idx += 1

                if idx != header.total_chunks:
                    raise DecryptionError("Chunk count mismatch")

                # Verify Merkle root *after* all chunks are in but before
                # the temp file is promoted to its final name. Constant-
                # time compare so an attacker probing root values can't
                # iteratively learn correct prefix bytes.
                #
                # The error is raised as DecryptionError (not
                # MerkleVerificationError) so all integrity failures
                # surface as a single class. A caller writing
                # `except DecryptionError` would previously have missed
                # the Merkle case despite MerkleVerificationError being a
                # CryptoError subclass. (Round-2 M1)
                computed_root = merkle_root(chunk_hashes)
                if not hmac.compare_digest(computed_root, header.merkle_root):
                    raise DecryptionError("Integrity check failed")

                out.flush()
                os.fsync(out.fileno())

            # Promote temp → final atomically only after every verification
            # has succeeded.
            os.replace(str(temp_path), str(output_path))
        except BaseException:
            # On any failure mid-write: remove the partial plaintext file
            # before propagating. This includes Merkle/signature/AEAD
            # failures and OS errors. FileNotFoundError is swallowed —
            # if the file never reached disk, there's nothing to clean.
            with contextlib.suppress(FileNotFoundError):
                os.unlink(str(temp_path))
            raise

    def decrypt_metadata(
        self,
        encrypted_metadata: bytes,
        meta_key: bytes,
        file_id: bytes,
    ) -> MetadataBlob:
        """Decrypt the metadata blob.

        Args:
            encrypted_metadata: nonce || ciphertext
            meta_key: metadata encryption key
            file_id: file ID for AAD binding

        Returns:
            deserialized MetadataBlob
        """
        # Upper-bound the input size so a hostile server can't ship a
        # multi-GiB "metadata" payload and force the AEAD to allocate
        # against it. The legitimate maximum is one padded bucket of
        # MAX_METADATA_BYTES plus the AEAD nonce/tag overhead.
        max_payload = MAX_METADATA_BYTES + NONCE_LEN + TAG_LEN
        if len(encrypted_metadata) > max_payload:
            raise DecryptionError("Metadata payload too large")
        if len(encrypted_metadata) < NONCE_LEN + TAG_LEN:
            raise DecryptionError("Metadata too short")

        nonce = encrypted_metadata[:NONCE_LEN]
        ciphertext = encrypted_metadata[NONCE_LEN:]

        aad = ChunkAAD(
            file_id=file_id,
            chunk_index=0xFFFFFFFF,
            total_chunks=0,
        ).serialize()

        padded = decrypt_chunk(meta_key, nonce, ciphertext, aad)
        meta_bytes = unpad(padded)
        return MetadataBlob.deserialize(meta_bytes)
