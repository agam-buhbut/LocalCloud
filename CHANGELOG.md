# Changelog

All notable changes to LocalCloud are recorded here. Format follows
Keep a Changelog; this project is pre-1.0 and not yet released.

## [Unreleased]

### Added
- X25519 enrollment with an Ed25519 self-signature and an authenticated,
  enumeration-resistant pubkey directory (`/api/users/*`); `share` now resolves
  and verifies recipient keys via the server instead of `--recipient-pubkey`.
- Owner file keys are wrapped to the owner's own identity (self-share row); the
  plaintext on-disk `keys.json` cache is gone. Unified, fail-closed key
  acquisition for owner + shared files; `migrate-keys` retires legacy caches.
- Metadata blob bound to the file's Merkle root under a dedicated AAD
  (`PROTOCOL_VERSION` 2).
- Route/property test tier; CI running the full Python + Rust toolchain.
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
- Timing-equalized share/unshare/auth and a constant-deadline, fixed-shape
  pubkey directory to suppress username-enumeration oracles.
- Fail-closed guards on enrollment and key migration.
- Server secret hygiene at the process level (`LimitCORE=0`, no swap,
  `LoadCredential=`); single-worker requirement documented (rate limiter +
  Argon2 cap are per-process).
- Session-secret rotation invalidates all outstanding tokens (tested).

### Fixed
- Review-remediation pass (branch `remediation/fix-review-findings`). Client UX
  and safety: confirm-before-destructive `rm`/`unshare` (with `--force`), clean
  error messages for a wrong key password and for malformed server responses,
  the session token validated before the key-password prompt, client-side
  `--limit`/`--offset`/filename bounds, and a plain-HTTP-to-non-loopback
  warning. Deploy templates: the AppArmor profile named so the acceptance check
  can match it, the `/srv/cloud` data-dir default, a strict single-`/32` peer
  check, IPv6 WireGuard handshake rate-limiting, backup WAL-staleness and
  consistency-window fixes, and `Wants=nftables` ordering.

### Documentation
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
