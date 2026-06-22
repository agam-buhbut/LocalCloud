# Code-now fix design — for review before implementation

_2026-06-22. Scope: the in-repo, owner-approved fixes from the production-readiness plan. Each is grounded in the actual code (line numbers verified). pyo3 upgrade approved; F2 = honest-minimum (no wire change); F6 + config-entropy dropped after grounding (see §"Dropped")._

## F1 — Implement the download owner-pubkey TOFU pin (HIGH)

**Problem (confirmed):** `client/cli.py:192-216 _resolve_owner_pubkey` returns `client.get_owner_pubkey(file_id)` (server-supplied) with **no persistence and no comparison**, while the docstring (`:197-199`) and the `download` docstring (`cli.py:414-419`) claim it is "TOFU-pinned." A hostile server can serve a different Ed25519 pubkey per download and re-sign the Merkle root, so the signature check protects nothing on non-owner downloads.

**Fix:**
- Add a pin store next to the key file: `Path(str(key_file) + ".owner_pins.json")`, a JSON map `{file_id: ed25519_pubkey_hex}`. Mode 0600, written atomically via the existing `_atomic_write_secret` (cli.py:45) — reuse, don't reinvent.
- In `_resolve_owner_pubkey`, after obtaining `pk` (override or server), before returning:
  - If `file_id` in pins: `hmac.compare_digest(pins[file_id], pk.hex())`; on mismatch raise `CryptoError("Owner key for <file_id> changed since first download — refusing (pass --sender-pubkey to override).")` → fail closed.
  - Else: record `pins[file_id] = pk.hex()` and persist.
  - `--sender-pubkey` override path also pins/compares (an explicit override that matches the pin is fine; a mismatch with an existing pin still fails closed unless... see open question Q1).
- Pin key = `file_id` because that is what the client reliably holds (`get_owner_pubkey` is per-file_id). TOFU = trust-on-first-download, consistency thereafter — exactly what the docstrings promise.

**Tests (new, in tests/test_cli.py or a new tests/test_owner_pin.py):**
- first download records a pin;
- second download with same key passes;
- second download with a *different* server key raises CryptoError and writes no output;
- `--sender-pubkey` override still works;
- corrupt/missing pin file is handled (treated as empty → re-TOFU, or fail? see Q2).

**Risks / open questions for review:**
- **Q1:** if a pin exists and the user passes a *different* `--sender-pubkey`, do we honor the explicit override (user knows best, out-of-band) or fail closed? Proposed: explicit override wins **and updates the pin** (out-of-band trust supersedes TOFU).
- **Q2:** unreadable/corrupt pin file → fail closed (refuse) or reset? Proposed: fail closed with a clear message (a corrupt pin store is suspicious).
- **Q3:** per-file_id vs per-owner pinning. Per-owner is stronger (one key per identity) but the client does not reliably know the owner account from `file_id`. Accept per-file_id for now; note as a possible refinement.

## F2 — Honest-minimum rollback fix (HIGH→doc/comment), NO wire change

**Problem (confirmed):** `client/encryptor.py:10` comment claims "Merkle root signed with Ed25519 to detect server rollback"; there is no cross-version anchor and `version_number` (set `=1` at `:206`, serialized in `MetadataBlob`) is never compared. The signature pins integrity within one version, not against replay of a stale validly-signed older version.

**Fix (no protocol change — keep the field to avoid a wire break):**
- Rewrite `encryptor.py:10` to state the true property: the signed Merkle root provides per-version integrity/authenticity; **whole-file rollback to an older validly-signed version is NOT detected** (out of scope; would need a monotonic anchor + client high-water mark).
- Correct `cli.py:414-419`'s "rollback"/TOFU conflation if needed (it conflates the F1 pin with rollback).
- Document `version_number` as a **reserved forward-compat placeholder, not a rollback control** at its definition in `shared/models.py` and in the README/threat-model "Accepted limitations."
- **Do NOT remove `version_number` from the wire format** (that would be a protocol/serialization change — out of the approved honest-minimum scope and a hard stop).

**Tests:** none required (comment/doc only). Existing serialization tests already pin the field's presence.

## F3 — Runtime single-process lock (MEDIUM)

**Problem (confirmed):** `server/auth.py:546-590 assert_single_worker` (called at `app.py:74`) only reads env vars (`WEB_CONCURRENCY`/`HYPERCORN_WORKERS`/`LOCALCLOUD_WORKERS`). `hypercorn --workers N` sets none of these → silently bypasses the guard; multi-process splits the authoritative in-memory rate limiter and Argon2 budget.

**Fix:** keep the env check (early, pre-build) AND add an OS-level exclusive lock that catches the `--workers` bypass at serve time:
- In `create_app`, register `@app.before_serving` to acquire `fcntl.flock(fd, LOCK_EX | LOCK_NB)` on a lockfile `f"{config.db_path}.worker.lock"`; on `BlockingIOError`/`OSError` raise `RuntimeError` (fail closed) naming the single-worker invariant. Store the fd on the app; release+close in `@app.after_serving`.
- Skip entirely when `config.db_path == ":memory:"` (tests / no real file).
- Rationale for before_serving: ASGI lifespan startup runs **once per worker process**, so the 2nd hypercorn worker fails to acquire → fail closed. `create_app` without serving (most unit tests) never acquires → no test contention.

**Tests (new):**
- acquiring the lock twice on the same lockfile path (simulating a 2nd worker) raises;
- `:memory:` path skips the lock;
- normal single-app serve acquires and releases cleanly.

**Risks for review:**
- Does any existing test create **two serving apps concurrently** in one process (which this would now block)? Must confirm the suite still passes. flock is per-OFD: sequential create→serve→shutdown across test modules releases between, so sequential is fine; only concurrent-serving would trip.
- Confirm hypercorn runs lifespan per worker (not once in a master) — if it ran once in a master, the flock would be held by the master and inherited; the before_serving approach still works because each worker re-runs startup. Validate on the real box (hardware item) but the unit behavior is sound.

## F5 — Fix the orphan-staging rmtree race (LOW)

**Problem (confirmed):** `server/storage.py:353-376 upload_init` does `makedirs` (`:355`) **then** `create_staging_upload` (`:361`). The background `cleanup_orphan_staging_dirs` (`:1606-1626`) rmtrees any canonical-id dir with no DB row → it can delete a live upload's staging dir in the window between makedirs and the row insert.

**Fix:** reverse the order so the scanner's "no row ⇒ orphan" invariant is always true for live uploads:
- `create_staging_upload(...)` FIRST; then `makedirs`. On `makedirs` failure, delete the just-created staging row (best-effort, logged) and re-raise.
- Update the comments at `:357-359` and at `cleanup_orphan_staging_dirs:1590-1593` to reflect the new ordering (a crash between row-insert and makedirs leaves a row-without-dir, which self-heals via `staging_expiry` row sweep — verify a row-expiry sweep exists; if not, the chunk handler already errors on a missing dir and the row expires).

**Tests (new regression):** insert a row, then run the orphan scanner, assert the (now-row-backed) staging dir is **not** removed; and the makedirs-failure path deletes the row.

**Risk for review:** confirm an expired-staging-row sweep exists so a row-without-dir (crash window) does not leak. If absent, prefer the alternative one-line fix: have the scanner **skip dirs younger than `staging_expiry`** (mtime guard) instead of reordering. Reviewer to pick.

## Minor — backup-copy fail-loud

**Problem (confirmed):** `deploy/backup/localcloud-backup-copy.sh:46` and `localcloud-restore-copy.sh:26` use `cp -a "$SRC/blobs/." "$DEST/blobs/" 2>/dev/null || true` under `set -eu` → a failed/partial blob copy is silent, yielding a meta.db-valid backup with missing ciphertext.

**Fix:** replace with an explicit guarded copy that fails loud:
```sh
if [ -d "$SRC/blobs" ]; then
    cp -a "$SRC/blobs/." "$DEST/blobs/"
fi
```
(`set -e` now aborts on a real copy error; the `[ -d ]` guard handles a legitimately-absent blobs dir, which was the only reason to swallow.)

**Tests:** `tests/test_backup_restore.py` exercises the happy path (unaffected). Do **not** modify the test.

## pyo3 0.24 → ≥0.29 upgrade (approved; empirical)

**Problem (confirmed by `cargo audit`):** pyo3 0.24.2 ⇒ RUSTSEC-2026-0176 + RUSTSEC-2026-0177. Fix: bump to `>=0.29`.

**Plan:** this is an empirical migration with real breaking API changes between 0.24 and 0.29 (Bound API maturity, `IntoPyObject`, deprecations). Steps:
- Bump `rust/keycore/Cargo.toml` pyo3 to `0.29` (or latest 0.2x clearing the advisory); update the comment.
- `maturin develop --release`; fix any compile breaks in `lib.rs`/binding code (the keycore surface is small: KeyPair methods, verify_signature).
- `cargo build`, `cargo clippy -D warnings`, `cargo test`, `cargo audit` (expect clean).
- Rebuild the editable install; run the **full Python suite** (the FFI boundary is exercised there).
- Do this on a branch/worktree so a failed migration is trivially revertible.

**Risk:** if the API churn is large, report back rather than forcing it. Hard requirement: zero behavior change to the crypto boundary; all 27 Rust + 334 Python tests stay green.

## README de-stale (doc-only)

Rewrite README PART I to match reality: §1 test counts (86/22 → 334/27), §11 known-gaps (drop owner self-wrap, pubkey directory, fuzz/property tests — now done; drop the deleted `requirements.txt` reference; keep public-visibility + version-history as accepted limitations with notes), §5.3/§5.4 (owner self-share is implemented), §7 (backup implemented in `deploy/backup/`), and the "deployment … NOT in this repo" line (deploy tree exists). Do this **last**, after the code fixes, so the gap list is accurate.

## api_client.py tests (additive coverage)

New `tests/test_api_client.py`: cover `_raise_for_status` (401→AuthError, 429→AuthError, 4xx/5xx→StorageError with/without JSON body), `_check_response` (bad JSON → StorageError), `_check_binary_response` (non-200 → StorageError), and a representative endpoint call (e.g. `get_owner_pubkey` parsing/validation, `login` token extraction) using httpx's `MockTransport` (no network). Real client object, mock only the transport boundary.

## Dropped after grounding (record as accepted, no code)
- **F6 (durable lockout):** already an in-code-documented accepted limitation (`auth.py:262-265`); DB-backed per-IP/per-username counters persist as defense-in-depth; restart is physical-console-only (not attacker-triggerable). A schema migration is not justified.
- **config session-secret entropy heuristic:** the operator is trusted in this threat model (adversary = server). The ≥64-char length floor already documents a 256-bit assumption; rely on the runbook's "generate via CSPRNG." No code.

## Deferred to wave 2 / owner-gated
pytest-cov CI gate, PyO3 inline tests, F4 (WAL read-conn — owner decision), F8 (peer-identity hardening — owner decision), Python lockfile (dep — owner decision), 2B public visibility (design — owner decision), all hardware acceptance items, external audit.
