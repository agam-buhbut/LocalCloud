================================================================================
LocalCloud — End-to-End-Encrypted Personal Cloud Storage
================================================================================

A personal cloud storage system in which the server is treated as a hostile
storage box: it holds only ciphertext and encrypted metadata, and all
confidentiality, integrity, forward secrecy, and metadata privacy terminate on
the client. The intended deployment is a single hardened Linux box reachable
only through WireGuard.

This README has two parts:

  PART I  — CURRENT IMPLEMENTATION
            What actually exists in this repository today, how to build/run/
            test it, the real wire protocol, the real crypto, the HTTP API,
            and the known gaps.

  PART II — TARGET DESIGN SPEC (ROADMAP)
            The full system vision, including the OS / network / deployment
            hardening that lives OUTSIDE this repository. This is the
            "final product" the implementation is working toward. PART I is
            the source of truth for what is built; PART II is the source of
            truth for what is intended.

When PART I and PART II disagree, PART I describes reality.


================================================================================
PART I — CURRENT IMPLEMENTATION
================================================================================

--------------------------------------------------------------------------------
1. What is implemented
--------------------------------------------------------------------------------

This repository implements the APPLICATION layer of the system: a client, a
server, a shared wire-format/crypto library, and a native Rust key-management
module. It does NOT provision the operating system, WireGuard, the firewall,
AppArmor, systemd units, disk encryption, or the backup system — those are
deployment concerns described in PART II and are not yet automated here.

Implemented and tested (334 Python tests + 27 Rust tests, all passing):

  * Per-file client-side encryption: independent random file_key + meta_key,
    per-chunk random 192-bit nonces, fixed 4 MiB chunks, AEAD chunk binding,
    BLAKE2b Merkle tree with an Ed25519-signed root, fully streaming I/O,
    fail-closed atomic decryption.
  * Native key management in Rust (keycore): X25519 + Ed25519 identity keys,
    Argon2id-encrypted key store, mlock + zeroize-on-drop + core-dump
    suppression, per-recipient key wrapping with ephemeral-static ECDH
    (sender-side forward secrecy).
  * Server (Quart/ASGI): chunked upload (init/chunk/finalize) with atomic
    directory-rename commit, ciphertext-only download, per-user ciphertext
    quota with transactional accounting, visibility-based access policy
    (private / shared / public), per-recipient wrapped-key storage, server-
    side Argon2id login, HMAC session tokens bound to the WireGuard peer,
    layered rate limiting, and timing-equalized endpoints to suppress
    username-enumeration oracles.
  * SQLite metadata store (WAL, schema v5 with migrations).
  * Operator admin CLI (physical-console-only user/account management).
  * Client CLI (init / login / upload / download / ls / rm / quota /
    share / unshare).

--------------------------------------------------------------------------------
2. Repository layout
--------------------------------------------------------------------------------

  shared/                 Wire format + crypto primitives (used by both ends)
    crypto.py             XChaCha20-Poly1305 AEAD, BLAKE2b, domain-separated
                          Merkle tree (build/prove/verify), server-side Argon2id
    models.py             Protocol constants, FileHeader / ChunkAAD /
                          MetadataBlob (canonical CBOR), padding, hardened CBOR
                          decoder, Merkle signing-input builder
    exceptions.py         Typed exception hierarchy (generic messages)
    io.py                 read_capped() — TOCTOU-safe size-capped file read

  rust/keycore/           Native key-management module (PyO3), Python pkg "keycore"
    src/identity.rs       Keypair lifecycle, Argon2id-encrypted store v2, mlock
    src/wrapping.rs       Ephemeral-static X25519 -> HKDF -> AEAD key wrapping
    src/signing.rs        Ed25519 sign / verify
    src/secure_memory.rs  mlock/munlock, constant-time eq, prctl no-core-dump
    src/lib.rs            PyO3 bindings (KeyPair class, verify_signature fn)

  server/                 Server application (Quart/ASGI, WireGuard-only)
    app.py                App factory, security headers, periodic cleanup task
    auth.py               Argon2id login, HMAC session tokens, rate limiting
    storage.py            Upload/download/delete/list/share blob engine
    database.py           SQLite data-access layer (WAL, schema v6)
    config.py             Env-driven config with secure defaults + validation
    policy.py             Visibility access control (private/shared/public)
    quota.py              Ciphertext-only quota accounting
    admin.py              Operator CLI (create-user, set-quota, ...)

  client/                 Client application
    cli.py                Click CLI entry point
    encryptor.py          Streaming per-file encrypt/decrypt engine
    keystore.py           KeyStore wrapper over keycore (auto-lock on idle)
    api_client.py         httpx HTTP client (connection-pooled)
    keymgmt.py            Unified fetch+unwrap of file keys (owner + recipient)

  tests/                  pytest suite (server, client, shared)
  pyproject.toml          Python project + tool config (sole source of truth)

--------------------------------------------------------------------------------
3. Build & install
--------------------------------------------------------------------------------

Prerequisites: Python >= 3.11 and a Rust toolchain (stable).

  # 1. Create and activate a virtualenv
  python -m venv .venv
  source .venv/bin/activate

  # 2. Install the Python project (server + client + shared) with dev tools
  pip install -e ".[dev]"

  # 3. Build and install the native keycore module into the venv
  pip install maturin
  cd rust/keycore && maturin develop --release && cd ../..

The `keycore` module is required by the client (encryptor, keystore, sharing).
The server does not import keycore. Tests that need keycore skip automatically
if it is not installed.

--------------------------------------------------------------------------------
4. Running the server
--------------------------------------------------------------------------------

The server refuses to start without a session secret of >= 64 characters and,
by default, refuses to bind to a public or unspecified address (it expects the
WireGuard interface address).

  # Generate a session secret (prefer a root-owned 0600 file in production)
  python -c 'import os; print(os.urandom(32).hex())' > /etc/localcloud/session.secret
  chmod 600 /etc/localcloud/session.secret

  # Point the server at it and run (development server)
  export LOCALCLOUD_SESSION_SECRET_FILE=/etc/localcloud/session.secret
  export LOCALCLOUD_BIND_HOST=10.0.0.1
  localcloud-server

For production, run the ASGI app under Hypercorn instead of the built-in
dev server, e.g.:

  hypercorn "server.app:create_app()" --bind 10.0.0.1:8443

(create_app() validates config and connects the DB at import-time of the app
object, so the secret env vars must be set before Hypercorn imports it.)

--------------------------------------------------------------------------------
5. Operator administration (physical console only)
--------------------------------------------------------------------------------

There is NO HTTP endpoint that creates or mutates accounts. All user state is
managed by the operator running the admin CLI directly against the database:

  python -m server.admin create-user alice                 # prompts for password
  python -m server.admin set-quota   alice 5368709120      # 5 GiB
  python -m server.admin register-pubkey alice <ed25519-hex>
  python -m server.admin disable-user alice                # revokes sessions too
  python -m server.admin bump-session alice                # revoke all live tokens
  python -m server.admin list-users
  python -m server.admin run-cleanup                        # one-shot GC

`register-pubkey` records the user's long-term Ed25519 identity key so that
other clients can fetch it (via the file's owner_pubkey endpoint) to verify
signatures on that owner's files. The user obtains the hex from `localcloud
init` output and gives it to the operator out-of-band.

--------------------------------------------------------------------------------
6. Client usage
--------------------------------------------------------------------------------

  # One-time: generate an identity keypair (encrypted at rest under a password)
  localcloud init
  # -> prints X25519 and Ed25519 public keys; give the Ed25519 key to the
  #    operator for register-pubkey, and your X25519 key to anyone who will
  #    share files WITH you.

  # Authenticate (session token saved next to the key file as ".session")
  localcloud --server http://10.0.0.1:8443 login alice

  # Upload (encrypt + stream). Owner keys are self-wrapped (no plaintext cache).
  localcloud upload ./report.pdf --visibility private

  # List / quota
  localcloud ls
  localcloud quota

  # Download + verify + decrypt
  localcloud download <file_id> ./report.pdf

  # Share with a recipient (needs their X25519 public key, obtained out-of-band)
  localcloud share <file_id> bob --recipient-pubkey <bob-x25519-hex>

  # Revoke a share (server-side only; see note in section 9)
  localcloud unshare <file_id> bob

  # Delete
  localcloud rm <file_id>

Default key file: ~/.localcloud/keys.enc (override with --key-file or
LOCALCLOUD_KEY_FILE). Default server: http://10.0.0.1:8443 (override with
--server or LOCALCLOUD_SERVER).

--------------------------------------------------------------------------------
7. Configuration (server environment variables)
--------------------------------------------------------------------------------

  LOCALCLOUD_SESSION_SECRET_FILE  Path to a root/owner-owned 0400/0600 file
                                  holding the HMAC session secret. Preferred
                                  over the env var (env is visible via /proc).
  LOCALCLOUD_SESSION_SECRET       HMAC session secret (>= 64 chars). Used only
                                  if the *_FILE form is unset.
  LOCALCLOUD_BIND_HOST            Bind address (default 10.0.0.1). Must be a
                                  private/loopback/link-local address unless
                                  LOCALCLOUD_ALLOW_PUBLIC_BIND=1.
  LOCALCLOUD_BIND_PORT            Bind port (default 8443).
  LOCALCLOUD_DATA_DIR             Base data dir (default /srv/cloud).
  LOCALCLOUD_BLOB_DIR             Finalized blobs (default <DATA_DIR>/blobs).
  LOCALCLOUD_STAGING_DIR          In-progress uploads (default <DATA_DIR>/staging).
                                  MUST be on the same filesystem as BLOB_DIR
                                  (finalize uses an atomic rename).
  LOCALCLOUD_DB_PATH              SQLite metadata DB (default <DATA_DIR>/meta.db).
  LOCALCLOUD_SESSION_LIFETIME     Token lifetime in seconds (60..86400, def 3600).
  LOCALCLOUD_DEFAULT_QUOTA        Default per-user quota in bytes (def 1 GiB).
  LOCALCLOUD_RATE_LIMIT_MAX       Max login attempts per window (def 5).
  LOCALCLOUD_RATE_LIMIT_WINDOW    Rate-limit window in seconds (def 60).
  LOCALCLOUD_STAGING_EXPIRY       Staging upload TTL in seconds (def 3600).
  LOCALCLOUD_MAX_CONTENT_LENGTH   Max request body in bytes (def 5 MiB).
  LOCALCLOUD_ALLOW_PUBLIC_BIND    Set to "1" to permit a public/unspecified bind.

--------------------------------------------------------------------------------
8. Wire protocol & cryptography (as implemented)
--------------------------------------------------------------------------------

Primitives:
  * AEAD:            XChaCha20-Poly1305 (192-bit nonce, 128-bit tag), via
                     PyNaCl on the Python side and the chacha20poly1305 crate
                     in Rust.
  * Hash / Merkle:   BLAKE2b-256.
  * Identity keys:   X25519 (key agreement) + Ed25519 (signatures), separate.
  * Password KDF:    Argon2id. Client key store: 512 MiB, t=3, p=1.
                     Server login: 128 MiB, t=3, p=1.
  * Key wrap KDF:    HKDF-SHA256.
  * Randomness:      OS CSPRNG (os.urandom / OsRng); aborts on entropy failure.

Per-file encryption (client/encryptor.py):
  * file_key, meta_key: independent 256-bit random keys per file. Never derived
    from filenames, timestamps, counters, or user secrets. Never reused.
  * file_id: 128-bit random.
  * Chunking: fixed CHUNK_SIZE = 4 MiB. The final (or only) chunk is zero-padded
    up to CHUNK_SIZE so every ciphertext block is the same length on the wire.
    The verified metadata's original_size is used to trim padding on download.
  * Per-chunk AAD (binds each chunk to its file/position/version), packed as
    ">16sIHI": file_id(16) || chunk_index(u32) || protocol_version(u16) ||
    total_chunks(u32). Metadata uses the sentinel chunk_index 0xFFFFFFFF.
  * On-wire chunk blob = nonce(24) || XChaCha20-Poly1305(file_key, nonce,
    padded_plaintext, AAD).
  * Integrity: BLAKE2b of each chunk blob forms the leaves of a Merkle tree
    (leaf tag 0x00, internal-node tag 0x01, odd nodes re-hashed under the node
    tag — closes the CVE-2012-2459 second-preimage class). The root is signed
    with the owner's Ed25519 key over a domain-separated input:
        "localcloud-merkle-v2" || file_id(16) || merkle_root(32) ||
        chunk_size(u64) || total_chunks(u64) || protocol_version(u16).
  * FileHeader (canonical CBOR): magic "LCLD", version, file_id, chunk_size,
    total_chunks, merkle_root, signature. Strict bounds + type checks on decode.
  * MetadataBlob (canonical CBOR, encrypted under meta_key, the whole blob
    padded to a power-of-two bucket from {1 KiB, 4 KiB, 16 KiB, 64 KiB} via a
    length-prefixed scheme): owner, visibility, shared_with, created_at,
    modified_at, original_size, blob_ids, version_number. NOTE: original_size
    is the EXACT plaintext size; it is carried encrypted inside the blob and is
    never sent to the server in clear. On-wire size leakage to the server is
    bounded only by the 4 MiB chunk granularity (total chunk count), not by
    this field.
  * Decryption order (fail-closed, atomic): parse/validate header -> verify
    Ed25519 root signature -> decrypt metadata -> per-chunk AEAD verify while
    streaming to a 0600 temp file -> recompute & constant-time-compare Merkle
    root -> only then os.replace into place. Any failure deletes the temp file.

Key wrapping for sharing (rust/keycore/src/wrapping.rs):
  * Ephemeral-static X25519 ECDH: a fresh ephemeral keypair per wrap gives
    sender-side forward secrecy (compromise of the sender's long-term key does
    not expose past wrapped bundles).
  * Wrapping key = HKDF-SHA256(ikm = ECDH, info = "localcloud-file-wrap-v2" ||
    sender_ed25519_pub(32) || file_id(16)).
  * AEAD AAD = "localcloud-file-wrap-aad-v3" || sender_pub(32) ||
    recipient_pub(32) || ephemeral_pub(32) || file_id(16).
  * Low-order / contributory-to-zero ECDH outputs are rejected (RFC 7748 §6.1).
  * Bundle (exactly 136 bytes) = ephemeral_pub(32) || nonce(24) ||
    ciphertext+tag(80). file_key||meta_key (64 bytes) is the plaintext.

Encrypted key store (rust/keycore/src/identity.rs), store version 2:
  * Argon2id(password, salt) -> master key -> XChaCha20-Poly1305 over a CBOR
    KeyBundle of the four 32-byte keys. Stored CBOR carries version, salt,
    Argon2 params, nonce, ciphertext. Argon2 params read from disk are bounds-
    checked (half..double of canonical) to prevent an OOM via a tampered store.
  * Private keys live in heap-stable, mlock'd, zeroize-on-drop storage; public/
    private consistency is checked in constant time on decrypt.

Authentication & sessions (server/auth.py):
  * Login: username + password over the tunnel. Argon2id verify runs against a
    real hash if the user exists, else a per-process random dummy hash, so the
    timing is independent of user existence. Concurrent Argon2id verifies are
    semaphore-bounded.
  * Session token: base64url(JSON).hex(HMAC-SHA256(secret, JSON)). Payload:
    {user_id, username, iat, exp, jti, peer, sv}. "peer" binds the token to the
    WireGuard source IP (mandatory). "sv" is the user's session_version; an
    operator bump or disable revokes all outstanding tokens immediately.
  * Rate limiting: authoritative in-memory composite (peer, username) limiter,
    plus DB-backed per-username and per-IP counters as defense-in-depth. Every
    failure path returns a uniform 401 to avoid leaking which gate tripped.

--------------------------------------------------------------------------------
9. Server HTTP API (as implemented)
--------------------------------------------------------------------------------

All endpoints except login require "Authorization: Bearer <token>" and a
WireGuard peer identity. All errors are generic.

  POST   /api/auth/login
         body {username, password} -> {token}

  POST   /api/files/upload/init
         body {filename, expected_chunks} -> {upload_id}
  POST   /api/files/upload/<upload_id>/chunk/<chunk_index>
         body: raw application/octet-stream ciphertext -> {chunk_hash}
  POST   /api/files/upload/<upload_id>/finalize
         body {file_id, total_chunks, file_header(hex), encrypted_metadata(hex),
               visibility, expected_hashes[]} -> {file_id}

  GET    /api/files                      list accessible files (limit/offset)
  GET    /api/files/<file_id>            metadata (header + encrypted metadata)
  GET    /api/files/<file_id>/owner_pubkey   owner's Ed25519 key (hex) for verify
  GET    /api/files/<file_id>/chunk/<chunk_index>   raw ciphertext chunk
  DELETE /api/files/<file_id>            delete (owner only; idempotent)

  POST   /api/files/<file_id>/share      body {shared_with, wrapped_keys(hex)}
  DELETE /api/files/<file_id>/share/<recipient_username>   revoke a share
  GET    /api/files/<file_id>/wrapped_keys    caller's wrapped keys for the file

  GET    /api/files/quota                {used_bytes, quota_bytes, available_bytes}

Server-side storage layout:
  <DATA_DIR>/meta.db                       SQLite metadata (WAL)
  <DATA_DIR>/blobs/<file_id>/<n>.bin       finalized ciphertext chunks
  <DATA_DIR>/staging/<upload_id>/<n>.bin   in-progress upload chunks

--------------------------------------------------------------------------------
10. Security properties & threat model (as implemented)
--------------------------------------------------------------------------------

The application layer is built to assume a malicious storage server with full
read/write access to ciphertext and metadata blobs, able to replay old state,
reorder/truncate chunks, and snapshot disks.

Holds against (at the application layer):
  * Server reading file contents or metadata (everything but the filename and
    coarse padded sizes is E2E-encrypted).
  * Chunk reorder / cross-file substitution (per-chunk AAD binding).
  * Rollback / truncation to old state (signed Merkle root + chunk-count check).
  * Retroactive decryption of shared bundles after sender long-term-key
    compromise (ephemeral-static wrapping).
  * Username enumeration via login or share/unshare (timing-equalized, uniform
    errors).
  * Token theft across peers (peer-bound tokens) and stale tokens after
    disable/rotate (session_version).

Out of scope / weak against: client-side compromise, live coercion while
online, total hardware loss, and traffic-analysis inference from filenames and
padded sizes (filenames are intentionally server-visible plaintext).

--------------------------------------------------------------------------------
11. Known gaps vs. the target spec (PART II)
--------------------------------------------------------------------------------

These are intentionally listed so the roadmap (PART II) is honest about the
distance remaining.

Deployment / infrastructure — present in deploy/ but UNVALIDATED on hardware:
  * The hostile-box tree (Debian hardening, LUKS2 + encrypted LVM, WireGuard
    transport, default-deny nftables, systemd units + scheduled-uptime timers +
    operator kill-switch, AppArmor profiles + systemd sandboxing, separate
    service users, encrypted-HDD backup flow, security logging) lives under
    deploy/. It is statically validated (shell/systemd/nftables/AppArmor parse
    clean) but has NOT been run on real hardware. First-deploy acceptance
    remains: external reachability (only WG port open), AppArmor enforce mode,
    the MemoryDenyWriteExecute-vs-argon2 risk, the kill-switch, and the
    backup→restore drill. See deploy/README.md.

Application-level limitations (consciously accepted unless noted):
  * Public visibility: the access policy authorizes any authenticated user to
    fetch a public file's ciphertext + metadata, but there is no automated
    per-user on-demand key wrapping — a non-owner obtains file/meta keys only
    via an explicit share. Full public key-delivery is deferred pending a
    security-reviewed key-committing-AEAD design (see the roadmap's "Accepted
    limitations"); Visibility.PUBLIC currently delivers no keys.
  * Whole-file rollback: a hostile server can serve an older, still-validly-
    signed file version; the client does not detect cross-version replay
    (per-version integrity IS enforced before decrypt). MetadataBlob.version_
    number is a reserved placeholder, never compared. See docs/threat-model.md.
  * Merkle range-proof downloads are not used: the client downloads all chunks
    and recomputes the root. merkle_proof()/verify_merkle_proof() exist but are
    unused by the download path.
  * MetadataBlob version_number / blob_ids are placeholders (no version history).
  * Storage/quota amplification: every chunk is zero-padded to the full chunk
    size (4 MiB) before encryption to hide the true file size, and quota is
    charged the padded size. A small file therefore consumes a 4 MiB blob and
    4 MiB of quota (a 1 GiB quota holds ~256 small files). Intentional
    size-hiding tradeoff; revisiting the granularity (configurable chunk size,
    or size-class padding for the final chunk, accepting a coarse size-class
    leak) is a future option. See docs/pentest-2026-06-22.md (M-1).

--------------------------------------------------------------------------------
12. Development
--------------------------------------------------------------------------------

  # Python tests
  pytest

  # Python toolchain (configured in pyproject.toml)
  black .          # format (line length 88)
  isort .          # import order (black profile)
  ruff check .     # lint (correctness-focused ruleset, incl. bandit-style "S")
  pylint server client shared
  pyright          # standard mode

  # Rust crate
  cd rust/keycore
  cargo test
  cargo clippy
  cargo fmt

Notes:
  * pyproject.toml is the single source of truth for dependencies and tool
    config (there is no requirements.txt). uv.lock is the committed,
    reproducible lockfile — recreate the env with `uv sync --extra dev`;
    refresh the lock after editing pyproject with `uv lock` (CI checks it
    for drift via `uv lock --check`).
  * Tests are deterministic and use tmp_path for filesystem state. Tests that
    require the native keycore module skip if it is not installed.


================================================================================
PART II — TARGET DESIGN SPEC (ROADMAP)
================================================================================

This is the original system specification — the "final product." Most of the
APPLICATION-layer crypto and server logic in sections 4–5 below is implemented
(see PART I). The machine/network/deployment hardening in sections 1–3 and 6–7
is the primary remaining work and is not yet automated in this repository.

Goal
  A barebones Debian host with encrypted LVM, hosting a globally reachable
  personal cloud storage server that is:
    - hardened and minimal (low attack surface)
    - reachable only through WireGuard
    - full E2EE storage (server cannot read contents or metadata except filenames)
    - public / shared / private file visibility rules
    - takeable offline on a schedule or instantly by the operator
    - physical-console-only administration
    - local encrypted backups to an internal HDD

1. Machine (server laptop)
  Minimal Debian: no GUI, no bluetooth/audio/camera/mic stacks; only essential
  packages (kernel, networking, storage, WireGuard, service deps). No sleep or
  suspend; fully awake when online, fully offline otherwise.
  Encrypted storage:
    - Primary disk (SSD): LUKS2 + encrypted LVM containing OS and live data.
    - Secondary disk (HDD): separate LUKS2 partition used only for encrypted
      backups, never auto-mounted.
    - Boot requires local unlock (physical presence).
  Physical-console-only admin: no admin SSH, no remote root.
  Strict service model: separate unprivileged users for tunnel and cloud
  service; the cloud service has no plaintext access to user data or metadata;
  the backup disk is only mountable by the operator from the console.
  Hardening: only one inbound UDP port open (WireGuard); everything else closed.
  AppArmor enforced; systemd sandboxing (no-new-privileges, no device access,
  no raw sockets); filesystem writes restricted to explicit directories;
  root filesystem mounted read-only with writable paths via tmpfs/bind mounts.
  Logging: minimal security logs only (connections, auth failures, quota
  events, backup events); no plaintext metadata.

2. Firewall + availability control layer
  Default-deny inbound via nftables; allow only the WireGuard UDP port.
  Scheduled uptime via systemd timers that add/remove the firewall rule
  controlling WireGuard availability; offline means no listening port and no
  established sessions. Operator kill-switch: a single command that removes the
  firewall rule, kills active sessions, and stops services. nftables rate
  limiting on the WireGuard port prior to the daemon.

3. Tunnel (WireGuard transport layer)
  Secure, authenticated, replay-resistant transport with minimal metadata
  leakage. WireGuard (Curve25519, ChaCha20-Poly1305) with built-in replay
  protection and forward secrecy; server public key pinned client-side; client
  authentication via WireGuard public-key allowlist; application auth inside the
  tunnel via username + password. Tunnel is transport-only: no file keys, no
  metadata keys, no persistence of secrets. Compromise of the tunnel does not
  compromise stored data.

4. Server application (cloud logic)   [IMPLEMENTED — see PART I §4,8,9]
  Runs only behind WireGuard.
  4.1 Core responsibilities: user management (accounts keyed by username; auth
      factors = WireGuard key + username + password); server-side per-user quota
      enforcement; storage of encrypted blobs and encrypted metadata blobs (the
      server cannot read contents or metadata except filenames); sharing rules
      (private / shared-to-specific-users / public-to-authenticated-users) with
      the server enforcing access policy only.
  4.2 Data model: plaintext on the server is limited to file_id, filename,
      owner, visibility mode, sharing list, timestamps, padded size, blob
      identifiers, and versioning/integrity data; everything else lives in the
      E2E-encrypted metadata blob.

5. E2EE design with forward secrecy   [IMPLEMENTED — see PART I §8]
  5.1 Identity keys: each user has a long-term encryption keypair (X25519) and a
      long-term signing keypair (Ed25519), separate from WireGuard keys, stored
      encrypted on the client.
  5.2 File/metadata encryption: per file, generate random file_key and meta_key;
      encrypt contents and metadata with XChaCha20-Poly1305; pad to fixed-size
      blocks; never reuse keys.
  5.3 Forward secrecy: per-file random keys, per-recipient key wrapping, no
      shared global keys, no server-side caching of wrapped keys; compromise of
      long-term keys does not allow retroactive decryption without the wrapped
      keys.
  5.4 Access control: private = keys wrapped to the owner's own identity;
      shared = keys wrapped individually to each recipient's public key;
      public = the server authorizes any authenticated user to FETCH the
      ciphertext + metadata, but there is NO automatic key delivery — only
      users explicitly shared-with can decrypt.
      (Owner decision 2026-06-22: automatic per-user key delivery for PUBLIC
      files is an ACCEPTED non-goal — it would require a security-reviewed
      key-committing-AEAD single-bundle design, since a publish-time fan-out is
      not confidential against the hostile server. Use `shared` to grant
      decryption. See PART I §11 and the roadmap "Accepted limitations".)

6. Client application   [IMPLEMENTED — see PART I §6,8]
  Local key management; local encryption/decryption; upload/download logic;
  keys encrypted at rest and unlocked only in memory; keys locked on inactivity;
  plaintext files exist only in memory or tmpfs. Upload = encrypt locally then
  upload ciphertext in chunks with integrity verification. Download = fetch
  ciphertext then decrypt locally with integrity verification. Sharing = client
  handles all key wrapping and signing. Quota display from the server. Secure
  deletion relies on encryption and key destruction, not physical shredding.

7. Backup system   [IMPLEMENTED — deploy/backup/, UNVALIDATED on hardware]
  Internal HDD backup only, LUKS2-encrypted, offline by default, mounted
  manually by the operator. Stores only encrypted blobs and encrypted metadata;
  no plaintext ever written. Flow: operator mounts disk, snapshots or rsyncs
  encrypted data, unmounts disk.

8. Operator controls
  Create and disable users; set quotas; revoke WireGuard keys; force the server
  offline instantly; mount/unmount the backup disk; rotate keys and credentials.
  (Account/quota/session controls are IMPLEMENTED in the admin CLI — PART I §5.
  WireGuard key revocation, offline kill-switch, and backup mounting are
  deployment-layer controls — see PART II §1–3,7.)

9. Security check (target)
  Strong against random scanning, brute force, server compromise reading data,
  disk theft, metadata inspection, replay, and retroactive decryption. Weak
  against total hardware loss, client-side compromise, and live coercion while
  online.

10. Design rule
  The server is a hostile storage box. All confidentiality, metadata privacy,
  and forward secrecy live on the client. The client provides cryptographic
  isolation at file granularity, strong misuse resistance, replay detection,
  authenticated chunking, strict key-lifecycle discipline, and deterministic
  failure behavior. The client must not implement custom cryptographic
  primitives; it relies on well-audited libraries and treats misuse resistance
  as a primary design constraint. Randomness acquisition aborts if the OS
  entropy source fails. All serialized structures are explicitly versioned;
  all parsers must be fuzz-tested; all cryptographic operations must be covered
  by property-based tests verifying nonce uniqueness, key isolation, and failure
  on corruption.
