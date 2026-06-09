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

### Removed
- Dead code: `client/sharing.py`, unused DB accessors and exceptions, and the
  unused Merkle range-proof functions (range proofs are out of scope).
- `requirements.txt` (pyproject is the single source of truth).
