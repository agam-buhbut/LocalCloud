# Changelog

All notable changes to LocalCloud are recorded here. Format follows
Keep a Changelog; this project is pre-1.0 and not yet released.

## [Unreleased]

### Added
- Android groundwork (written 2026-06-29, merged 2026-10). The Rust code in
  `rust/` is now one Cargo workspace with one `Cargo.lock`:
  `keycore-core` holds the crypto, `keycore` is the Python module on top of it
  (its Python API is unchanged), and the new `keycore-mobile` is an Android
  binding (UniFFI) with generated Kotlin code in `rust/bindings-kotlin/`.
  Nothing is built for Android yet. Tests in `format_pin.rs` check that the
  split did not change the byte format of key stores or wrapped keys. The
  core-dump guard now also covers Android.
- Tests for `keycore-mobile`: key generation, sign and verify, wrap and unwrap,
  and that every error is the same single opaque error.
- X25519 enrollment with an Ed25519 self-signature and an authenticated,
  enumeration-resistant pubkey directory (`/api/users/*`); `share` now resolves
  and verifies recipient keys via the server instead of `--recipient-pubkey`.
- Owner file keys are wrapped to the owner's own identity (self-share row); the
  plaintext on-disk `keys.json` cache is gone. Unified, fail-closed key
  acquisition for owner + shared files; `migrate-keys` retires legacy caches.
- Metadata blob bound to the file's Merkle root under a dedicated AAD
  (`PROTOCOL_VERSION` 2).
- Route/property test tier; a CI workflow for the full Python + Rust toolchain
  (its Python job could not run until the 2026-10 fix listed under Fixed).
- Configurable Argon2 verification concurrency
  (`LOCALCLOUD_ARGON2_MAX_CONCURRENT`).
- Deployment tree (`deploy/`): WireGuard, nftables, hardened systemd units +
  uptime timers, AppArmor profile, OS-hardening + disk docs, journald policy,
  and an operator kill-switch.
- Encrypted backup/restore system (offline LUKS2 HDD) with a tested
  consistent-snapshot data-copy core.
- Docs: threat model, operations + key-rotation runbooks, release checklist,
  performance benchmarks.

### Changed
- Rust dependencies (2026-10, from the new shared `Cargo.lock`): `zeroize`
  1.8.2 → 1.9.0, now also for the desktop build, and a new crate, `uniffi`
  0.31.2, used only by `keycore-mobile`.
- **Wire/schema (breaking):** metadata `PROTOCOL_VERSION` 1→2 (hard cutover, no
  v1 path) and DB schema → v6 (X25519 columns). Pre-existing v1 blobs / v5 DBs
  require the migration.
- Ed25519 verification uses `verify_strict`.
- `list_user_files` rewritten to avoid materializing the whole public corpus
  (per-branch ordered-index limit + dedup): ~5× faster at large public corpora
  and no longer scaling with public-file count.
- `PRAGMA synchronous=NORMAL` under WAL (per-chunk file fsync retained).
- God-functions decomposed (`upload_finalize`, `cli.upload/download`); shared
  canonicalizers and a single timing-equalization helper.

### Security
- Unwrapped file keys are wiped again (2026-10). During the Android split,
  `IdentityKeyPair::unwrap_file_keys` started to return plain arrays, so the
  caller's copies of the file and metadata keys were not wiped from memory.
  It now returns them in `Zeroizing` wrappers again, and a test checks that.
- Five locked Python packages raised to versions that fix known advisories
  found by pip-audit (2026-10): anyio 4.14.2, h2 4.4.1 and hpack 4.2.0 (used
  at run time), pip 26.2 and urllib3 2.8.0 (dev tools only).
- HIGH (2026-06-29 pentest): `share` to a user found through the server's
  directory trusted keys that the server controls. A hostile server could swap
  in its own keys and then read the shared file. The client now pins each
  recipient's Ed25519 key after the first successful share
  (`<key-file>.recipient_pins.json`) and refuses a later change.
  `share --recipient-pubkey` still takes a key from outside the server.
- MEDIUM (2026-06-29 pentest): if a client disconnected during upload
  finalize, the upload could stay marked as "finalizing", and its disk use then
  escaped the quota. Finalize now always clears that mark.
- Login timing (2026-06-28 pentest, P1): replies that skipped the Argon2id
  check came back sooner, which showed when the rate limit had tripped. The
  server now measures its real Argon2id cost at start-up and makes every login
  reply take at least that long.
- The per-username login limit now counts per WireGuard peer and username, so
  one peer can no longer lock another peer out of an account (AUTH-1).
- Timing-equalized share/unshare/auth and a constant-deadline, fixed-shape
  pubkey directory to suppress username-enumeration oracles.
- Fail-closed guards on enrollment and key migration.
- Server secret hygiene at the process level (`LimitCORE=0`, no swap,
  `LoadCredential=`); single-worker requirement documented (rate limiter +
  Argon2 cap are per-process).
- Session-secret rotation invalidates all outstanding tokens (tested).

### Fixed
- CI never passed (fixed 2026-10). The Python job installed packages into the
  runner's own Python, and `maturin develop` refuses to run outside a
  virtualenv, so the job stopped before lint, type checks, tests or pip-audit.
  The job now builds `.venv` from `uv.lock` with uv and runs every check in it,
  so the checks and pip-audit see the locked versions. The Rust job now checks
  the whole workspace (all three crates).
- First deploy on real hardware (2026-06-28). The systemd unit could not start:
  the syscall filter killed the Hypercorn worker (D1), and the app refused the
  0440 secret file from systemd `LoadCredential=` (D2). The AppArmor profile
  did not attach, so the server ran unconfined (D3). Two false alarms in the
  acceptance check were fixed (D4, D5), and deploy/README.md now warns that
  the firewall makes the box reachable only through WireGuard (D6). After the
  fixes, the acceptance check passed 14 of 14 on the box. See
  `docs/pentest-2026-06-28.md`.
- Server (2026-06-28): a staging temp file leaked when a chunk write failed,
  and finalize could publish a file whose chunk file was missing on disk; it
  now cleans up and refuses (409).
- Client (2026-06-28/29): the plain-HTTP warning now shows once per run, when
  connecting, instead of on every command; `enroll` and `migrate-keys` show a
  clean error when the network fails; the key unlock (about 4 seconds) now
  prints "Unlocking key store (Argon2id, this takes a few seconds)…"; and the
  error for a missing owner key on download now names the command to register
  your own key.
- CI (2026-06-28): a coverage floor (82%) and a check that keycore really
  imports, so a broken build cannot silently skip the crypto tests.
- Review fixes (2026-06-28). Client UX and safety: confirm-before-destructive
  `rm`/`unshare` (with `--force`), clean error messages for a wrong key
  password and for malformed server responses, the session token validated
  before the key-password prompt, client-side `--limit`/`--offset`/filename
  bounds, and a plain-HTTP-to-non-loopback warning. Deploy templates: the
  AppArmor profile named so the acceptance check can match it, the
  `/srv/cloud` data-dir default, a strict single-`/32` peer check, IPv6
  WireGuard handshake rate-limiting, backup WAL-staleness and
  consistency-window fixes, and `Wants=nftables` ordering.

### Documentation
- README.txt rewritten in plain words (2026-10) and brought up to date: the
  real-hardware run, `recipient_pins.json`, the Rust workspace, how to build,
  and how to run the CI checks yourself.
- `wrapping.rs`, and the doc of the Python method `KeyPair.wrap_file_keys`,
  now say plainly that the sender key in a wrapped bundle is only a label,
  not proof of who made it (from the 2026-06-29 deep pentest).
- `deploy/README.md` no longer says the server does not need keycore. It
  does (its user directory checks enroll signatures with it), so the install
  step now builds keycore into the server's venv too.
- `docs/release-checklist.md` now names `rust/Cargo.lock` and the Rust checks
  for the whole workspace.
- New reports: `docs/pentest-2026-06-28.md` and
  `docs/prod-readiness-2026-06-29.md`; measured performance in
  `docs/benchmarks.md`.
- README: to download your own files you must first `register-pubkey` your own
  key, and a recipient must `enroll` before you can share with them through the
  directory.
- Corrected comments: the `build_metadata_aad` comment now says that only the
  domain tag separates metadata from chunks (`METADATA_CHUNK_INDEX` is not in
  the metadata AAD), and the key unlock takes about 4 seconds, not 1.
- Corrected README PART I drift: SQLite schema version (now v6), references to
  removed symbols (`client/sharing.py`, `merkle_proof()`/`verify_merkle_proof()`),
  and the dangling `unshare` cross-reference.
- Documented previously code-only client mechanics: TOFU owner-pubkey pinning
  (`<key-file>.owner_pins.json`, the fail-closed "owner identity changed"
  refusal, and the `--sender-pubkey` override), the `.session` token (location,
  WireGuard peer-binding, expiry), and the keystore auto-lock timeout.
- Closed the resolved Python-lockfile checklist item (`uv.lock` committed and
  CI-gated via `uv lock --check`); added a benchmarks reproducibility note, an
  internal-review-label glossary (`#Fxx` / `Round-N` / `item-2x`), and recorded
  the MemoryDenyWriteExecute-vs-argon2 clearance (pentest V15).

### Removed
- Dead code: `client/sharing.py`, unused DB accessors and exceptions, and the
  unused Merkle range-proof functions (range proofs are out of scope).
- `requirements.txt` (pyproject is the single source of truth).
- The old per-crate lockfile `rust/keycore/Cargo.lock` (replaced by
  `rust/Cargo.lock`).
