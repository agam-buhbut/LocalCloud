================================================================================
LocalCloud — End-to-End-Encrypted Personal Cloud Storage
================================================================================

LocalCloud stores your files on a server you own, but it does not trust that
server. The server only ever holds encrypted data. All encryption, signing
and checking happens on your own computer (the "client"). So the server
cannot read your files or their details, and it cannot change them without
the client noticing. This is called end-to-end encryption (E2EE).

It is built for one owner (the operator) and a few users. The server is meant
to run on one hardened Linux box that you can reach only through WireGuard
(a VPN).

This README has two parts:

  PART I  — WHAT EXISTS TODAY
            What is in this repository, how to build, run and test it, the
            file format and crypto as built, the HTTP API, and the known
            gaps.

  PART II — TARGET DESIGN (ROADMAP)
            The full plan, including how the box itself should be set up.
            PART I says what is built. PART II says what is intended.

When PART I and PART II disagree, PART I is right.


================================================================================
PART I — WHAT EXISTS TODAY
================================================================================

--------------------------------------------------------------------------------
1. What is built
--------------------------------------------------------------------------------

This repository holds:

  * the client: the `localcloud` command-line program;
  * the server: a web app that stores encrypted files;
  * shared code that both use (file format and crypto helpers);
  * keycore: Rust code that holds and uses your private keys;
  * deploy/: scripts and config files that set up the box (OS hardening,
    WireGuard, firewall, systemd services, AppArmor (a Linux tool that limits
    what a program may touch), encrypted backups).

Tests and checks:

  * About 480 Python tests and 36 Rust tests (as of 2026-10-04).
  * The CI workflow (.github/workflows/ci.yml) runs all of them on every
    push, together with lint, type and supply-chain checks. Section 12 shows
    how to run the same checks on your own machine.
  * The deploy/ files were first run on a real Debian 13 box on 2026-06-28.
    That run found bugs, which were fixed. After the fixes, the acceptance
    check passed all 14 of its checks. Some checks need the owner at the box
    and were not run yet (see section 11). Details:
    docs/pentest-2026-06-28.md.
  * There has been no external security audit yet.

What the code does:

  * Encrypts each file on the client before upload:
      - each file gets its own random file key and metadata key;
      - the file is cut into fixed 4 MiB chunks, and each chunk gets its own
        random 192-bit nonce (a "number used once");
      - each chunk is tied to its file and to its place in the file, so
        chunks cannot be swapped or reordered;
      - a BLAKE2b Merkle tree (a tree of hashes over all chunks) is built,
        and its root is signed with the owner's Ed25519 key;
      - data is streamed, never held whole in memory;
      - decryption is all or nothing: if any check fails, you get no file.
  * Keeps private keys in Rust (keycore):
      - X25519 keys (for key exchange) and Ed25519 keys (for signatures);
      - on disk they are encrypted under your password with Argon2id (a
        slow password hash that also needs a lot of memory, to resist
        guessing);
      - in memory they are locked so they are never swapped to disk
        (mlock), wiped when no longer needed (zeroize), and core dumps are
        turned off;
      - to share a file, the client wraps (encrypts) the file's keys for
        each recipient with a fresh one-time key pair (ephemeral-static
        ECDH). So if the sender's long-term key leaks later, old shares stay
        safe (sender-side forward secrecy).
  * The server (Quart, a Python web framework for async apps):
      - upload in three steps: init, chunks, finalize. Finalize makes the
        file appear in one atomic directory rename;
      - download sends only ciphertext;
      - a quota per user, counted in ciphertext bytes; quota changes are
        made inside database transactions;
      - access rules by visibility: private, shared or public;
      - one stored wrapped-key bundle per recipient;
      - login checked with Argon2id on the server;
      - session tokens signed with HMAC (a keyed hash), tied to your
        WireGuard peer;
      - several layers of rate limiting;
      - sensitive endpoints take the same time either way, so timing does
        not reveal whether a username exists.
  * A user directory: each user can publish ("enroll") their X25519 public
    key, signed with their Ed25519 key, so others can share files with them.
  * A SQLite database for metadata (in write-ahead-log "WAL" mode, schema
    version 6, with migrations).
  * An admin command for the operator, run only at the box's own console.
  * Client commands: init, login, enroll, upload, download, ls, rm, quota,
    share, unshare, migrate-keys.

--------------------------------------------------------------------------------
2. Repository layout
--------------------------------------------------------------------------------

  shared/                 Code used by both client and server
    crypto.py             XChaCha20-Poly1305 encryption, BLAKE2b hashing,
                          the Merkle tree root, and the server's Argon2id
    models.py             Protocol constants; FileHeader, ChunkAAD and
                          MetadataBlob (in canonical CBOR, a compact binary
                          format like JSON); padding; a strict CBOR
                          decoder; the input that the Merkle root
                          signature covers
    exceptions.py         Typed exceptions with generic messages
    io.py                 read_capped(): a safe, size-capped file read
    file_ids.py           The one rule for valid file ids and their standard
                          form
    usernames.py          The one rule for usernames, and the input that the
                          enroll signature covers

  rust/                   Rust code: one Cargo workspace (rust/Cargo.toml)
                          with one lockfile (rust/Cargo.lock)
    keycore-core/         The crypto itself, in plain Rust (no Python or
                          Android code)
      src/identity.rs     Key pairs, the password-protected key store
                          (format v2), mlock
      src/wrapping.rs     Key wrapping for sharing: one-time X25519 key ->
                          HKDF -> AEAD
      src/signing.rs      Ed25519 sign and verify
      src/secure_memory.rs  mlock / munlock, constant-time compare, no core
                          dumps
      src/format_pin.rs   Tests that freeze the byte formats of the key store
                          and of wrapped keys
    keycore/              The Python module "keycore" (built with PyO3 and
                          maturin, tools that turn Rust code into a Python
                          module): a thin layer over keycore-core with the
                          KeyPair class and verify_signature()
    keycore-mobile/       The Android binding (built with UniFFI, a tool
                          that makes Kotlin code that calls Rust): a thin
                          layer over keycore-core. Not built for Android yet.
    bindings-kotlin/      Kotlin code generated from keycore-mobile

  server/                 The server (Quart; runs behind WireGuard only)
    app.py                Creates the app; security headers; a regular
                          cleanup task
    auth.py               Argon2id login, HMAC session tokens, rate limiting,
                          the single-worker check
    users.py              The user directory: X25519 enroll and public-key
                          lookup
    storage.py            Upload, download, delete, list and share
    database.py           SQLite access (WAL, schema v6)
    config.py             Settings from environment variables, with safe
                          defaults and checks
    policy.py             Access rules by visibility (private / shared /
                          public)
    quota.py              Quota accounting (ciphertext bytes only)
    timing.py             The "constant deadline" helper that makes
                          sensitive endpoints take a fixed minimum time
    state.py              Typed app state, built once at start-up
    admin.py              Operator commands (create-user, set-quota, ...)

  client/                 The client
    cli.py                The `localcloud` command (Click)
    encryptor.py          Streaming encrypt and decrypt of one file
    keystore.py           The key store over keycore (locks itself when idle)
    api_client.py         HTTP client (httpx; reuses connections)
    keymgmt.py            Fetch and unwrap file keys (owner and recipient);
                          the enroll signature

  deploy/                 Box setup: OS hardening, WireGuard, the nftables
                          firewall (the Linux packet filter), systemd units
                          and timers, AppArmor, logging, backup scripts and
                          the acceptance check (see deploy/README.md)
  docs/                   Threat model, runbooks, release checklist,
                          benchmarks and pentest reports
  tests/                  The pytest suite (server, client, shared)
  pyproject.toml          Python project and tool settings (the single source
                          of truth)
  uv.lock                 The exact locked versions of all Python packages

--------------------------------------------------------------------------------
3. Build and install
--------------------------------------------------------------------------------

You need Python 3.11 or newer, a stable Rust toolchain, and uv (a Python
package manager that installs from uv.lock).

  # 1. Make .venv with the exact versions in uv.lock (the project plus the
  #    dev tools)
  uv sync --extra dev

  # 2. Build the keycore Rust module and install it into .venv
  uv pip install maturin
  uv run maturin develop --release -m rust/keycore/Cargo.toml

keycore and maturin are not in uv.lock, so running `uv sync` again removes
them. Repeat step 2 after it.

Without uv, the older way still works. It installs the newest allowed
versions instead of the locked ones:

  python -m venv .venv
  source .venv/bin/activate
  pip install -e ".[dev]"
  pip install maturin
  maturin develop --release -m rust/keycore/Cargo.toml

Both the client and the server need keycore. The client uses it for the key
store, in the per-file encrypt and decrypt engine, and for the key wrapping
used for sharing. The server uses it in the user directory, to check enroll
signatures. Install keycore before you run the tests: without it, the test
run stops with import errors.

--------------------------------------------------------------------------------
4. Running the server
--------------------------------------------------------------------------------

The server will not start without a session secret of at least 64
characters. By default it also refuses to listen on a public or "any"
address; it expects the WireGuard address.

  # Make a session secret (in production, use a root-owned file with mode
  # 0600; see LOCALCLOUD_SESSION_SECRET_FILE in section 7)
  python -c 'import os; print(os.urandom(32).hex())' > /etc/localcloud/session.secret
  chmod 600 /etc/localcloud/session.secret

  # Point the server at it and start the development server
  export LOCALCLOUD_SESSION_SECRET_FILE=/etc/localcloud/session.secret
  export LOCALCLOUD_BIND_HOST=10.0.0.1
  localcloud-server

For production, run the app under Hypercorn with exactly one worker, the way
the systemd unit in deploy/systemd/localcloud.service does:

  hypercorn --workers 1 --bind 10.0.0.1:8443 "server.app:create_app()"

create_app() checks the config and opens the database when Hypercorn loads
it, so set the secret's environment variable before you start Hypercorn.

Use exactly one worker. The rate limiter and the Argon2id limit live inside
the server process, so more workers would multiply the limits. The server
stops at start-up if WEB_CONCURRENCY, HYPERCORN_WORKERS or LOCALCLOUD_WORKERS
asks for more than one worker. A second worker process also fails to get a
lock file and stops.

--------------------------------------------------------------------------------
5. Operator administration (only at the box's console)
--------------------------------------------------------------------------------

No HTTP endpoint creates or changes accounts. The operator manages all users
by running the admin command directly against the database:

  python -m server.admin create-user alice                 # asks for a password
  python -m server.admin set-quota   alice 5368709120      # 5 GiB
  python -m server.admin register-pubkey alice <ed25519-hex>
  python -m server.admin disable-user alice                # ends her sessions
  python -m server.admin bump-session alice                # ends all her tokens
  python -m server.admin list-users
  python -m server.admin run-cleanup                       # one-time cleanup

`register-pubkey` stores the user's long-term Ed25519 identity key. Other
clients fetch it (through the file's owner_pubkey endpoint) to check the
signatures on that user's files. The server also needs it before the user can
`enroll`. The user gets the hex key from the output of `localcloud init` and
gives it to the operator by some other trusted channel ("out of band").

--------------------------------------------------------------------------------
6. Client usage
--------------------------------------------------------------------------------

  # Once: make your identity key pair. It is saved encrypted under a
  # password.
  localcloud init
  # -> prints your X25519 and Ed25519 public keys. Give the Ed25519 key to
  #    the operator for `register-pubkey`. Give your X25519 key to anyone who
  #    will share files with you out of band (see `share` below).

  # Log in. The session token is saved next to the key file as ".session".
  localcloud --server http://10.0.0.1:8443 login alice

  # Once, after the operator has registered your Ed25519 key: publish your
  # X25519 key in the server directory, so others can share files with you.
  localcloud enroll alice

  # Upload (encrypt and stream). Your own copy of the file keys is wrapped to
  # your own key and stored on the server, so no plaintext key is kept on
  # disk.
  localcloud upload ./report.pdf --visibility private

  # List files and show your quota
  localcloud ls
  localcloud quota

  # Download, check and decrypt.
  # FIRST: the file owner's Ed25519 key must be registered on the server
  # (the operator's `register-pubkey` step in section 5). For your OWN files
  # that means your own key. If you are the only user, you are also the
  # operator, so run `python -m server.admin register-pubkey <you>
  # <your-ed25519-hex>` yourself (`init` prints the hex). Without it, the
  # download stops with "Server has no registered identity key for this
  # file's owner", and the message names the command to fix it.
  # The owner's signing key is pinned on the first successful download (see
  # "Trust" below). Pass --sender-pubkey <ed25519-hex> to check the first
  # download against a key you got out of band, or to pin again after a real
  # change of the owner's key.
  localcloud download <file_id> ./report.pdf

  # Share with a user. By default the client looks the user up in the server
  # directory, so they must have run `localcloud enroll <name>` first.
  localcloud share <file_id> bob
  # Or pass their X25519 key, which you got out of band, and skip the
  # directory:
  localcloud share <file_id> bob --recipient-pubkey <bob-x25519-hex>

  # Stop sharing (on the server only; see "Revocation" below)
  localcloud unshare <file_id> bob

  # Delete
  localcloud rm <file_id>

  # Older versions kept plaintext <file_id>.keys.json files. This moves those
  # keys to the server (wrapped to your own key) and deletes the files. It is
  # a normal delete, not a secure wipe, so treat old key files as possibly
  # copied already.
  localcloud migrate-keys

`rm` and `unshare` ask before they act; add --force to skip the question.
`ls` shows 50 files at a time; use --limit (1-200) and --offset to page.

Commands that use your keys first unlock the key store. That takes a few
seconds (about 4 s, measured) because of Argon2id, and the client prints
"Unlocking key store (Argon2id, this takes a few seconds)…" meanwhile.

Default key file: ~/.localcloud/keys.enc (change it with --key-file or
LOCALCLOUD_KEY_FILE). Default server: http://10.0.0.1:8443 (change it with
--server or LOCALCLOUD_SERVER). If the server address is plain HTTP and not
on this machine, the client prints a warning once per run.

Client files (all written with mode 0600, next to the key file):
  * <key-file>                      your identity keys, encrypted with
                                    Argon2id (default ~/.localcloud/keys.enc)
  * <key-file dir>/.session         the session token from `login` (default
                                    ~/.localcloud/.session). The server ties
                                    it to your WireGuard source IP, so it
                                    only works from the same peer. It
                                    expires after the server's session
                                    lifetime (LOCALCLOUD_SESSION_LIFETIME,
                                    default 1 hour); then run `login` again.
  * <key-file>.owner_pins.json      pinned file owners: a JSON map of
                                    file_id -> the owner's Ed25519 key. See
                                    "Trust" below.
  * <key-file>.recipient_pins.json  pinned share recipients: a JSON map of
                                    username -> that user's Ed25519 key. See
                                    "Trust" below.

Trust (key pinning, "TOFU"):
  TOFU means "trust on first use". The first time the client sees someone's
  key, it saves it. Later it refuses a different key.

  Owner keys (download). The Ed25519 key that signs a file's Merkle root is
  what protects you from a hostile server. On the first SUCCESSFUL download
  of a file, the client saves that key in owner_pins.json. On every later
  download it compares the key the server sends with the saved one (in
  constant time, so the timing reveals nothing). If they differ, it stops,
  decrypts nothing and says: "Owner identity key for <file_id> changed since
  first download — refusing (the server may be hostile)". The first download
  trusts the server; after that, the pin only proves the key has not changed.
  Pass `download --sender-pubkey <ed25519-hex>` to check the first download
  against a key you got out of band, or to replace a pin on purpose after a
  real change of the owner's key (it warns that it overwrites the saved pin).

  Recipient keys (share). By default `share` gets the recipient's keys from
  the server directory and checks the recipient's Ed25519 signature over
  their X25519 key. That check alone is not enough, because the server also
  supplies the Ed25519 key. So after the first successful share to a user,
  the client saves that user's Ed25519 key in recipient_pins.json. If a
  later share gets a different key from the server, it stops, wraps nothing
  and says: "Recipient identity key for <user> changed since the first share
  — refusing (the server may be hostile)". The first share trusts the server.
  `share --recipient-pubkey <hex>` skips the directory and the pin, and uses
  the key you got out of band.

  A broken or oversized pin file also makes the client stop. Delete it on
  purpose to pin again. (See docs/runbooks/key-rotation.md.)

Key locking (auto-lock):
  After you unlock the key store, it locks itself again after 5 minutes
  without use, and the private keys are wiped from memory. A command that
  hits a locked store fails with "Key store is locked". Just run the command
  again: it asks for the key password and unlocks a fresh copy.

Revocation:
  `unshare` only removes the recipient's wrapped-key row on the server.
  Anyone who already downloaded the wrapped keys keeps them and can still
  decrypt that version of the file offline. To truly revoke, upload the file
  again; that makes a new random file key.

--------------------------------------------------------------------------------
7. Configuration (server environment variables)
--------------------------------------------------------------------------------

  LOCALCLOUD_SESSION_SECRET_FILE  Path to the file that holds the HMAC session
                                  secret. Use this instead of the plain
                                  variable below, because other processes can
                                  read environment variables (/proc). The
                                  file must be mode 0400 or 0600, or 0440 if
                                  its group is the service's group or root
                                  (that is how systemd LoadCredential=
                                  delivers it).
  LOCALCLOUD_SESSION_SECRET       The HMAC session secret itself (>= 64
                                  characters). Used only if the *_FILE form
                                  is not set.
  LOCALCLOUD_BIND_HOST            Address to listen on (default 10.0.0.1). It
                                  must be a private, loopback or link-local
                                  address unless LOCALCLOUD_ALLOW_PUBLIC_BIND=1.
  LOCALCLOUD_BIND_PORT            Port to listen on (default 8443).
  LOCALCLOUD_DATA_DIR             Base data folder (default /srv/cloud).
  LOCALCLOUD_BLOB_DIR             Finished files (default <DATA_DIR>/blobs).
  LOCALCLOUD_STAGING_DIR          Uploads in progress (default
                                  <DATA_DIR>/staging). It MUST be on the same
                                  filesystem as BLOB_DIR, because finalize
                                  uses an atomic rename.
  LOCALCLOUD_DB_PATH              The SQLite database (default
                                  <DATA_DIR>/meta.db).
  LOCALCLOUD_SESSION_LIFETIME     Token lifetime in seconds (60 to 86400,
                                  default 3600).
  LOCALCLOUD_DEFAULT_QUOTA        Default quota per user, in bytes (default
                                  1 GiB).
  LOCALCLOUD_RATE_LIMIT_MAX       Login attempts allowed per window
                                  (default 5).
  LOCALCLOUD_RATE_LIMIT_WINDOW    Rate-limit window in seconds (default 60).
  LOCALCLOUD_STAGING_EXPIRY       How long an unfinished upload is kept, in
                                  seconds (default 3600).
  LOCALCLOUD_MAX_CONTENT_LENGTH   Largest request body in bytes (default
                                  5 MiB).
  LOCALCLOUD_ARGON2_MAX_CONCURRENT  How many Argon2id login checks may run
                                  at once (default 4, at least 1). Each one
                                  uses about 128 MiB of memory.
  LOCALCLOUD_ALLOW_PUBLIC_BIND    Set to "1" to allow a public or "any"
                                  address.
  LOCALCLOUD_WORKERS              Optional worker count. Like
                                  WEB_CONCURRENCY and HYPERCORN_WORKERS, the
                                  server refuses to start if it is more than
                                  1 (see section 4).

--------------------------------------------------------------------------------
8. File format and cryptography (as built)
--------------------------------------------------------------------------------

Building blocks:
  * Encryption: XChaCha20-Poly1305, an AEAD (192-bit nonce, 128-bit tag).
    AEAD means each encrypted piece also carries a check value, so any
    change to it is detected. PyNaCl on the Python side; the
    chacha20poly1305 crate in Rust.
  * Hash and Merkle tree: BLAKE2b-256.
  * Identity keys: X25519 (key agreement) and Ed25519 (signatures), kept
    separate.
  * Password hashing: Argon2id. Client key store: 512 MiB, t=3, p=1. Server
    login: 128 MiB, t=3, p=1.
  * Key derivation for key wrapping: HKDF-SHA256.
  * Randomness: the operating system's secure random source (os.urandom in
    Python, OsRng in Rust). If it fails, the program stops instead of going
    on.

Per-file encryption (client/encryptor.py):
  * file_key and meta_key: two independent random 256-bit keys per file.
    They are never derived from file names, times, counters or user secrets,
    and never reused.
  * file_id: 128 random bits.
  * Chunks: a fixed CHUNK_SIZE of 4 MiB. The last (or only) chunk is padded
    with zeros up to 4 MiB, so every encrypted chunk has the same size on the
    wire. On download, original_size from the checked metadata is used to cut
    off the padding.
  * Each chunk's AAD (extra data the AEAD checks but does not encrypt) ties
    the chunk to its file, position and version. It is packed as ">16sIHI":
    file_id(16) || chunk_index(u32) || protocol_version(u16) ||
    total_chunks(u32).
  * The metadata blob has its own AAD: "localcloud-meta-aad-v2" ||
    file_id(16) || merkle_root(32) || protocol_version(u16). That separate
    tag is what keeps metadata and chunks apart. (METADATA_CHUNK_INDEX,
    0xFFFFFFFF in shared/models.py, is not part of it; it only feeds a check,
    run when the module loads, that chunk indexes fit in 32 bits.)
  * A chunk on the wire = nonce(24) || XChaCha20-Poly1305(file_key, nonce,
    padded_plaintext, AAD).
  * Integrity: the BLAKE2b hashes of the chunk blobs are the leaves of a
    Merkle tree. Leaves are tagged 0x00 and inner nodes 0x01, and a lone
    (odd) node is hashed again under the node tag. This closes the
    CVE-2012-2459 kind of second-preimage attack. The owner's Ed25519 key
    signs the root over this input:
        "localcloud-merkle-v2" || file_id(16) || merkle_root(32) ||
        chunk_size(u64) || total_chunks(u64) || protocol_version(u16).
  * FileHeader (canonical CBOR): magic "LCLD", version, file_id, chunk_size,
    total_chunks, merkle_root, signature. Decoding checks strict limits and
    types.
  * MetadataBlob (canonical CBOR, encrypted under meta_key): owner,
    visibility, shared_with, created_at, modified_at, original_size,
    blob_ids, version_number. Before encryption the blob gets a 4-byte length
    prefix and random padding, up to the smallest of 1, 4, 16 or 64 KiB that
    fits (bigger metadata goes up to a multiple of 64 KiB). NOTE:
    original_size is the EXACT plaintext size, but it travels only inside the
    encrypted blob and is never sent to the server in clear. What the server
    can learn about file size is limited by the 4 MiB chunk size (the number
    of chunks), not by this field.
  * Decryption order (all or nothing): read and check the header -> verify
    the Ed25519 root signature -> decrypt the metadata -> check each chunk's
    AEAD while streaming into a temp file with mode 0600 -> rebuild the
    Merkle root and compare it in constant time -> only then move the file
    into place (os.replace). Any failure deletes the temp file.

Key wrapping for sharing (rust/keycore-core/src/wrapping.rs):
  * A fresh one-time X25519 key pair for every wrap (ephemeral-static ECDH)
    gives sender-side forward secrecy: if the sender's long-term key leaks,
    past wrapped bundles stay safe.
  * Wrapping key = HKDF-SHA256(ikm = ECDH result, info =
    "localcloud-file-wrap-v2" || sender_ed25519_pub(32) || file_id(16)).
  * AEAD AAD = "localcloud-file-wrap-aad-v3" || sender_pub(32) ||
    recipient_pub(32) || ephemeral_pub(32) || file_id(16).
  * The sender key in the HKDF info and the AAD is only a label. It does not
    prove who made the bundle: wrapping needs only the recipient's public
    key, so anyone can make a bundle that names any sender. The label only
    stops a bundle from being moved over to a different sender. Who wrote a
    file is proven by the owner's signature on the Merkle root and the
    owner-key pin (section 6).
  * ECDH results that are all zero (from low-order keys) are refused
    (RFC 7748 §6.1).
  * A bundle is exactly 136 bytes: ephemeral_pub(32) || nonce(24) ||
    ciphertext+tag(80). The plaintext is file_key || meta_key (64 bytes).
  * The unwrapped keys come back in Zeroizing wrappers, so Rust wipes them
    when they are dropped. The copies handed to Python (or Kotlin) cannot be
    wiped.

Encrypted key store (rust/keycore-core/src/identity.rs), store version 2:
  * Argon2id(password, salt) -> master key -> XChaCha20-Poly1305 over a CBOR
    KeyBundle of the four 32-byte keys. The stored CBOR holds the version,
    salt, Argon2 settings, nonce and ciphertext. Argon2 settings read from
    disk must lie between half and double the normal values, so a tampered
    store cannot make the next unlock run out of memory.
  * Private keys live in memory that does not move, is locked (mlock) and is
    wiped on drop. On decrypt, the client checks in constant time that the
    public and private keys match.
  * Tests in format_pin.rs freeze the byte formats of the key store and of
    wrapped bundles, so old key stores keep working.

Login and sessions (server/auth.py):
  * Login: username and password over the tunnel. If the user exists, the
    server runs Argon2id against the real hash; if not, against a random
    dummy hash. So the time does not depend on whether the user exists. A
    limit caps how many Argon2id checks run at once.
  * Every login reply is padded to a fixed minimum time. At start-up the
    server measures how long its Argon2id check really takes and raises that
    minimum to match (server/timing.py).
  * Session token: base64url(JSON) "." hex(HMAC-SHA256(secret, JSON)). The
    JSON holds {user_id, username, iat, exp, jti, peer, sv}. "peer" ties the
    token to your WireGuard source IP (always required). "sv" is the user's
    session_version: when the operator bumps it or disables the user, all
    their tokens stop working at once.
  * Rate limiting: the limit that decides is kept in memory and counted per
    (peer, username). Database counters, per (peer, username) and per IP, add
    a second layer. Every failure returns the same 401, so you cannot tell
    which limit was hit.

--------------------------------------------------------------------------------
9. Server HTTP API (as built)
--------------------------------------------------------------------------------

Every endpoint except login needs "Authorization: Bearer <token>" and a
WireGuard peer identity. All error messages are generic.

  POST   /api/auth/login
         body {username, password} -> {token}

  POST   /api/files/upload/init
         body {filename, expected_chunks} -> {upload_id}
  POST   /api/files/upload/<upload_id>/chunk/<chunk_index>
         body: raw application/octet-stream ciphertext -> {chunk_hash}
  POST   /api/files/upload/<upload_id>/finalize
         body {file_id, total_chunks, file_header(hex), encrypted_metadata(hex),
               visibility, expected_hashes[]} -> {file_id}

  GET    /api/files                      list the files you can access
                                         (limit/offset)
  GET    /api/files/<file_id>            metadata (header + encrypted metadata)
  GET    /api/files/<file_id>/owner_pubkey   the owner's Ed25519 key (hex), to
                                         check the signature
  GET    /api/files/<file_id>/chunk/<chunk_index>   one raw ciphertext chunk
  DELETE /api/files/<file_id>            delete (owner only; safe to repeat)

  POST   /api/files/<file_id>/share      body {shared_with, wrapped_keys(hex)}
  DELETE /api/files/<file_id>/share/<recipient_username>   stop a share
  POST   /api/files/<file_id>/self_keys  store the owner's own wrapped keys
  GET    /api/files/<file_id>/wrapped_keys    your wrapped keys for the file

  GET    /api/files/quota                {used_bytes, quota_bytes, available_bytes}

  POST   /api/users/enroll_x25519        body {x25519_pubkey, self_sig}: publish
                                         your own X25519 key
  GET    /api/users/<username>/pubkeys   {ed25519, x25519, self_sig} (hex). The
                                         reply has the same size and timing
                                         for every name, so it does not show
                                         who exists.
  GET    /api/users/enrolled             users who enrolled, with their public
                                         keys (limit/offset)

Where the server keeps data:
  <DATA_DIR>/meta.db                       SQLite metadata (WAL)
  <DATA_DIR>/blobs/<file_id>/<n>.bin       finished ciphertext chunks
  <DATA_DIR>/staging/<upload_id>/<n>.bin   chunks of uploads in progress

--------------------------------------------------------------------------------
10. Security properties and threat model (as built)
--------------------------------------------------------------------------------

The application assumes a malicious storage server. It can read and write all
ciphertext and metadata blobs, replay old state, reorder or cut chunks, and
copy disks.

What holds (at the application level):
  * The server cannot read file contents or metadata. Only the file name and
    the rough, padded size are visible to it; everything else is
    end-to-end encrypted.
  * Chunks cannot be reordered or swapped in from other files (each chunk's
    AAD ties it to its place).
  * The server cannot cut a file short or mix in chunks from an older state
    without being caught (signed Merkle root plus a chunk-count check). It
    can still serve a whole older version of a file; see section 11.
  * Shared bundles stay safe even if the sender's long-term key leaks later
    (one-time wrapping keys).
  * Usernames cannot be found by probing login, share or unshare (same
    timing, same errors).
  * A stolen token does not work from another peer (tokens are tied to the
    peer), and old tokens stop working after a disable or a rotation
    (session_version).
  * Shared files: once a recipient is pinned after a genuine first contact
    (or you used --recipient-pubkey), the server cannot swap in its own key
    to read what you share with them. The very first directory share trusts
    the server (see "Trust" in section 6 and docs/threat-model.md).

Out of scope, or weak against: a compromised client, being forced to unlock
while online, losing all the hardware, and guesses from traffic patterns,
file names and padded sizes (file names are plaintext to the server on
purpose).

--------------------------------------------------------------------------------
11. Known gaps compared with the target (PART II)
--------------------------------------------------------------------------------

These are listed so that the roadmap (PART II) is honest about what is left.

Deployment (deploy/):
  * deploy/ holds the box setup: Debian hardening, LUKS2 (Linux disk
    encryption) and encrypted LVM (deploy/os/DISKS.md), WireGuard, a
    default-deny nftables firewall, systemd units with scheduled up-time
    timers and an operator kill-switch, AppArmor profiles and systemd
    sandboxing, separate service users, the encrypted-HDD backup flow, and
    security logging. See deploy/README.md.
  * It was first run on a real Debian 13 box on 2026-06-28, using the real
    systemd unit, WireGuard and AppArmor. That run found two bugs that
    stopped the service from starting and one that left it unconfined by
    AppArmor; all were fixed and checked on the box. The acceptance check
    then passed 14 of 14 (docs/pentest-2026-06-28.md). The
    MemoryDenyWriteExecute setting works with Argon2 (checked on real
    hardware in the 2026-06-22 pentest, item V15), so keep it on.
  * Not yet run, because they need the owner at the real box: LUKS2 unlock
    at the console and surviving a reboot; an nmap scan from a second host
    (only the WireGuard port should be open); the live kill-switch and the
    up-time toggle; the full backup drill with the real LUKS backup disk.
  * There has been no external security audit. Get one before you store real
    data.

Application limits (accepted on purpose unless noted):
  * Public files: the access rules let any logged-in user fetch a public
    file's ciphertext and metadata, but nothing hands out the keys
    automatically. A non-owner gets the file and metadata keys only through
    an explicit share. Full key delivery for public files is put off until
    there is a security-reviewed design based on a key-committing AEAD (see
    the roadmap's "Accepted limitations"). Visibility.PUBLIC currently
    delivers no keys.
  * Rolling back a whole file: a hostile server can serve an older version
    that is still validly signed. The client does not detect that it got an
    older version (each version's own integrity IS checked before
    decryption). MetadataBlob.version_number is a placeholder and is never
    compared. See docs/threat-model.md.
  * Downloads do not use Merkle range proofs: the client downloads all
    chunks and rebuilds the root from scratch. (The unused range-proof helper
    functions were removed; see CHANGELOG.md.)
  * MetadataBlob version_number and blob_ids are placeholders (there is no
    version history).
  * Storage and quota cost: every chunk is padded to the full 4 MiB before
    encryption, to hide the real file size, and the quota is charged the
    padded size. So a small file uses a 4 MiB blob and 4 MiB of quota (a
    1 GiB quota holds about 256 small files). This trade-off is on purpose.
    A future option is to change the size steps (a configurable chunk size,
    or size classes for the last chunk, which would leak a rough size
    class). See docs/pentest-2026-06-22.md (M-1).
  * Smaller open items from the 2026-06-29 review are listed in
    docs/prod-readiness-2026-06-29.md.

--------------------------------------------------------------------------------
12. Development: running the checks yourself
--------------------------------------------------------------------------------

These are the same checks that CI runs (.github/workflows/ci.yml). Run them
from the repository root after the steps in section 3.

  # Python
  uv lock --check                      # uv.lock matches pyproject.toml
  uv run black --check .               # formatting (line length 88)
  uv run isort --check --profile black .   # import order
  uv run ruff check .                  # lint (correctness rules, including
                                       # the security ("S") rules)
  uv run pylint client server shared   # deeper lint (must score >= 9.8)
  uv run pyright                       # types (standard mode)
  uv run pytest -q --cov=client --cov=server --cov=shared --cov-fail-under=82
  uv run pip-audit                     # known problems in installed packages

  # Rust (the whole workspace)
  cargo fmt    --manifest-path rust/Cargo.toml --all --check
  cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets \
      -- -D warnings
  cargo test   --manifest-path rust/Cargo.toml --workspace
  cargo audit  --file rust/Cargo.lock  # needs cargo-audit installed

  # Kotlin bindings match the Rust code. The Kotlin code in
  # rust/bindings-kotlin/ is generated from the keycore-mobile crate. These
  # commands make it again and fail if the result is not what is committed.
  # Run them inside rust/.
  cd rust
  cargo build --locked -p keycore-mobile
  rm -rf bindings-kotlin
  lib="${CARGO_TARGET_DIR:-target}/debug/libkeycore_mobile.so"
  cargo run --locked -p keycore-mobile --features cli --bin uniffi-bindgen -- \
      generate --library "$lib" --language kotlin --out-dir bindings-kotlin \
      --no-format
  git diff --exit-code -- bindings-kotlin   # prints nothing when all is well
  cd ..

The Rust tests take several minutes in a debug build, because some of them
run the real Argon2id (512 MiB). The Kotlin check also takes a few minutes the
first time, because it builds the code generator. If it shows a difference,
the file in your working copy has already been rewritten: read the change and
commit it.

Notes:
  * pyproject.toml is the single source of truth for dependencies and tool
    settings (there is no requirements.txt). uv.lock is the committed lock
    file that makes the environment repeatable: recreate the environment
    with `uv sync --extra dev`, and refresh the lock with `uv lock` after you
    edit pyproject.toml. CI fails if the two drift apart (`uv lock --check`).
  * rust/Cargo.lock is the one lock file for all three Rust crates.
  * Tests are deterministic and keep files in pytest's tmp_path.
  * docs/release-checklist.md lists everything to check before a release.
  * Comments tagged `#Fxx`, `Round-N` or `item-2x` (for example `#F8`,
    `Round-3 H8`, `item 2A`) point to internal security-review findings,
    rounds of fixes, and roadmap work items. There is no public issue
    tracker, so there is nothing outside the repository to look up.


================================================================================
PART II — TARGET DESIGN (ROADMAP)
================================================================================

This is the original specification: the "final product". The application in
sections 4 to 6 is built (see PART I). Much of the box setup (sections 1 to 3)
and the backup system (section 7) is in deploy/, as scripts, config files and
step-by-step notes. It ran on a test box on 2026-06-28, but some checks still
need the owner at the real box (see PART I §11).

Goal
  A bare Debian host with encrypted LVM, running a personal cloud storage
  server that can be reached from anywhere and is:
    - hardened and minimal (little to attack);
    - reachable only through WireGuard;
    - fully end-to-end encrypted (the server cannot read contents or
      metadata, except file names);
    - able to make files public, shared or private;
    - able to go offline on a schedule, or at once when the operator says so;
    - administered only at the physical console;
    - backed up, encrypted, to an internal HDD.

1. Machine (a laptop used as the server)
  A minimal Debian: no GUI, no Bluetooth, audio, camera or microphone stacks;
  only what is needed (kernel, networking, storage, WireGuard and the
  service's dependencies). No sleep or suspend: fully awake when online,
  fully offline otherwise.
  Encrypted storage:
    - Main disk (SSD): LUKS2 with encrypted LVM, holding the OS and live data.
    - Second disk (HDD): a separate LUKS2 partition used only for encrypted
      backups, never mounted automatically.
    - Booting needs a local unlock (someone physically present).
  Admin only at the physical console: no admin SSH, no remote root.
  Strict service model: separate unprivileged users for the tunnel and for
  the cloud service. The cloud service never has plaintext access to user
  data or metadata. Only the operator, at the console, can mount the backup
  disk.
  Hardening: only one inbound UDP port is open (WireGuard); everything else
  is closed. AppArmor is enforced. systemd sandboxing (no new privileges, no
  device access, no raw sockets). Writes are allowed only to listed folders.
  The root filesystem is mounted read-only, with writable paths through tmpfs
  or bind mounts.
  Logging: only a few security logs (connections, login failures, quota
  events, backup events); no plaintext metadata.

2. Firewall and availability control
  nftables drops all inbound traffic by default and allows only the
  WireGuard UDP port. systemd timers add and remove the firewall rule for
  WireGuard to set the hours when the server is up. Offline means no
  listening port and no open sessions. An operator kill-switch is one
  command that removes the firewall rule, ends active sessions and stops the
  services. nftables also rate-limits the WireGuard port before traffic
  reaches the daemon.

3. Tunnel (WireGuard)
  A secure, authenticated transport that resists replays and leaks little
  metadata. WireGuard (Curve25519, ChaCha20-Poly1305) has built-in replay
  protection and forward secrecy. The client pins the server's public key.
  Clients are allowed in by a list of WireGuard public keys. Inside the
  tunnel, the app logs users in with username and password. The tunnel only
  carries traffic: it holds no file keys, no metadata keys and stores no
  secrets. Breaking the tunnel does not expose stored data.

4. Server application (cloud logic)   [BUILT — see PART I §4, 8, 9]
  Runs only behind WireGuard.
  4.1 Main jobs: user management (accounts keyed by username; to log in you
      need your WireGuard key, username and password); a quota per user,
      enforced by the server; storage of encrypted blobs and encrypted
      metadata blobs (the server cannot read contents or metadata, except
      file names); sharing rules (private / shared with named users / public
      to logged-in users), where the server only enforces who may fetch
      what.
  4.2 Data model: the server sees in plaintext only the file_id, file name,
      owner, visibility, sharing list, timestamps, padded size, blob ids,
      and version and integrity data. Everything else is in the end-to-end
      encrypted metadata blob.

5. End-to-end encryption with forward secrecy   [BUILT — see PART I §8]
  5.1 Identity keys: each user has a long-term encryption key pair (X25519)
      and a long-term signing key pair (Ed25519). They are separate from the
      WireGuard keys and stored encrypted on the client.
  5.2 File and metadata encryption: for each file, make a random file_key
      and meta_key; encrypt the contents and the metadata with
      XChaCha20-Poly1305; pad to fixed-size blocks; never reuse keys.
  5.3 Forward secrecy: random keys per file, key wrapping per recipient, no
      shared global keys, and no caching of wrapped keys on the server. If a
      long-term key leaks, old files cannot be decrypted without the wrapped
      keys.
  5.4 Access control: private = keys wrapped to the owner's own identity;
      shared = keys wrapped separately to each recipient's public key;
      public = the server lets any logged-in user FETCH the ciphertext and
      metadata, but there is NO automatic key delivery. Only users the file
      was explicitly shared with can decrypt it.
      (Owner decision, 2026-06-22: automatic key delivery to every user for
      PUBLIC files is an ACCEPTED non-goal. It would need a security-reviewed
      single-bundle design with a key-committing AEAD, because handing out
      keys at publish time is not confidential against a hostile server. Use
      `shared` to give someone the ability to decrypt. See PART I §11 and the
      roadmap's "Accepted limitations".)

6. Client application   [BUILT — see PART I §6, 8]
  Manages keys, encrypts and decrypts locally, uploads and downloads. Keys
  are encrypted at rest and unlocked only in memory, and they lock again
  when idle. Plaintext files exist only in memory or in tmpfs. Upload =
  encrypt locally, then upload the ciphertext in chunks with integrity
  checks. Download = fetch the ciphertext, then decrypt locally with
  integrity checks. Sharing = the client does all key wrapping and signing.
  The quota is shown from the server. Secure deletion relies on encryption
  and destroying keys, not on physically shredding data.

7. Backup system   [BUILT — deploy/backup/; the full drill with the real
                    backup disk is not done yet]
  Backups go only to the internal HDD, encrypted with LUKS2, offline by
  default and mounted by hand by the operator. They hold only encrypted blobs
  and encrypted metadata; plaintext is never written. Steps: the operator
  mounts the disk, takes a snapshot or rsyncs the encrypted data, and
  unmounts the disk.

8. Operator controls
  Create and disable users; set quotas; revoke WireGuard keys; take the
  server offline at once; mount and unmount the backup disk; rotate keys and
  credentials. (Account, quota and session controls are BUILT in the admin
  command — PART I §5. Revoking WireGuard keys, the offline kill-switch and
  mounting the backup disk are box-level controls in deploy/ — see PART II
  §1–3 and 7.)

9. Security goals (target)
  Strong against random scanning, password guessing, a compromised server
  reading data, disk theft, metadata snooping, replays, and decrypting old
  data later. Weak against losing all the hardware, a compromised client,
  and being forced to unlock while online.

10. Design rule
  The server is a hostile storage box. All confidentiality, metadata privacy
  and forward secrecy live on the client. The client keeps each file
  cryptographically separate, resists misuse, detects replays, checks every
  chunk, handles keys strictly through their whole life, and fails in
  predictable ways. The client must not build its own crypto primitives; it
  uses well-audited libraries and treats misuse resistance as a main design
  goal. If the OS random source fails, getting randomness aborts. Every
  stored or sent structure has an explicit version. Every parser must be
  fuzz-tested. Every crypto operation must be covered by property-based
  tests that check nonce uniqueness, key isolation, and failure on
  corruption.
