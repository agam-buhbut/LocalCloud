# Security / Crypto Pass (Sectors B auth, D shared-crypto, E rust-keycore)

Separate plan per the goal. **No public signature changes.** TDD. Specific exceptions only. These three sectors own disjoint files and may run as parallel agents.

## B — server-auth (server/auth.py, server/timing.py; tests test_auth_*, test_rate_limit_rows, test_api_auth, test_timing_equalization)

### AUTH-1 (MEDIUM) — cross-peer account-lockout DoS
**Decision:** peer-scope the legacy per-username DB gate so it matches the #H11 composite limiter's blast radius (preserves brute-force protection; removes cross-peer lockout; honours the documented guarantee). NOT removing the gate, NOT going global.
**Fix:** the per-username branch in `check_rate_limit` (auth.py:370-373) and `db.count_recent_attempts(username, window)` must become `(ip_address, username)`-scoped — add an `ip_address` arg to `count_recent_attempts` (database.py:597-606 SQL gains `AND ip_address = ?`) and pass the peer at the call site (auth.py:668-679). The per-IP gate and composite limiter are unchanged.
**Test (test_rate_limit_rows.py / test_api_auth.py):** peer P1 floods 5 failed logins for victim "alice"; a login attempt for "alice" from a *different* peer P2 with the correct password must NOT be rejected by the per-username gate (reaches verify). Before fix: rejected (lockout). After: allowed. Also keep the same-peer lockout test green.

### AUTH-2 (LOW) — reject-sleep budget shorter than real Argon2 verify; inaccurate comment
**Fix:** correct the comment at auth.py:39-44 to state the true relationship (the 150 ms cap bounds early-reject variance; it is NOT equal to the ~250 ms Argon2 verify path, and the equalization that matters for enumeration is that existing/non-existing users both run Argon2). Minimal: comment accuracy + (optional) raise the login early-reject budget toward the measured verify time if cheap. Do not claim indistinguishability the code can't deliver.
**Test:** none required for a comment; if the budget is changed, keep timing_equalization tests green.

### AUTH-3 (LOW perf/sec) — dummy Argon2 hash computed on the event loop on first unknown-user login
**Fix:** pre-warm `_get_dummy_hash()` once inside `init_auth` (runs at startup before serving) so the ~250 ms hash is a one-time startup cost off the request path, removing the event-loop block and the cold-start timing artifact.
**Test (test_auth_*):** assert the dummy hash is populated after `init_auth` (or that the first unknown-user login does not trigger a fresh hash). Keep enumeration tests green.

## D — shared-crypto (shared/crypto.py, models.py, io.py, file_ids.py, exceptions.py; tests test_models, test_property_*)

### CRYPTO-1 (LOW) — RecursionError can escape `_safe_cbor_loads`
**Fix:** add `RecursionError` to the except tuple in `_safe_cbor_loads` (models.py:257-281), mapping to `MalformedRequestError`. (Optionally also bound decode independently, but the catch is the minimal correct fix.)
**Test (test_property_parsers.py / test_models.py):** a deeply-nested-but-under-cap CBOR payload raises `MalformedRequestError`, never `RecursionError`.

### CRYPTO-2 (LOW) — broad `except Exception` around FileHeader.validate()
**Fix:** narrow models.py:389 to `except ProtocolError as e:` (validate() only raises ProtocolError). Keep `raise MalformedRequestError(...) from e`.
**Test:** malformed header still → MalformedRequestError; add a check that a genuine non-ProtocolError bug would propagate (e.g. via a unit asserting the catch type).

### CRYPTO-3 (LOW) — broad `except Exception` in encrypt_chunk
**Fix:** narrow crypto.py:74 to the specific exceptions PyNaCl/argument errors raise (`nacl.exceptions.CryptoError`, `TypeError`, `ValueError`), matching `decrypt_chunk` (crypto.py:100).
**Test (test_property_crypto / test_models):** encrypt/decrypt round-trip still green; a wrong-typed arg raises the specific error.

### IO-1 (LOW) — read_capped weaker than secret-file reader
**Fix:** in shared/io.py:24-31 add an `S_ISREG` fstat check and loop the read until EOF or cap (handle short reads). Keep the cap semantics.
**Test (new/extend):** read_capped on a regular file returns full content; refuses a non-regular path; respects the cap.

### EXC-1 (INFO) — divergent canonicalizer exception types
**Fix:** align file_ids.py / usernames.py canonicalizers to raise the same boundary exception family (or document the divergence). Lowest priority; do only if zero-risk.

## E — rust-keycore (rust/keycore/**; cargo fmt/clippy -D warnings/test)

### CRYPTO-4 (INFO) — wrap_file_keys doc block consumed by REQUIRED_FILE_ID_LEN const
**Fix:** move `pub const REQUIRED_FILE_ID_LEN` above its own one-line doc and restore the multi-line `///` doc block (incl. the `ephemeral_pubkey || nonce || ciphertext+tag` wire-format note) directly above `pub fn wrap_file_keys` (wrapping.rs:79-87).

### CRYPTO-5/6/7 (INFO) — document accepted tradeoffs (no behavior change)
- CRYPTO-5: note mlock-failure-non-fatal is backstopped by systemd `LimitMEMLOCK`/RLIMIT (identity.rs:191-200) — add a `///` note + a one-line pointer in deploy docs (coordinate with deploy sector, doc only).
- CRYPTO-6: keep/clarify the "decrypt_from_store must not be exposed across a network/remote trust boundary" contract comment (identity.rs:286-317).
- CRYPTO-7: document that unwrapped file/meta keys necessarily cross FFI into non-zeroizable Python bytes (lib.rs:151-154) as an architectural boundary note.

## Verify
B/D: scoped pytest for the owned tests, then full suite. E: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` in rust/keycore. Sector end folds into the wave toolchain run + adversarial diff review.
