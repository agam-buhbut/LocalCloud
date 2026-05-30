# LocalCloud: Current State → Final Product Implementation Plan

> **For agentic workers:** This is a multi-subsystem ROADMAP. Each phase below is
> a separate deliverable; before executing a phase, expand it into its own
> bite-sized task plan (`docs/superpowers/plans/YYYY-MM-DD-<phase>.md`) using
> superpowers:writing-plans, then execute with superpowers:subagent-driven-development
> or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take LocalCloud from a working, well-hardened application core to the
full "hostile-storage-box" personal-cloud product described in README PART II —
WireGuard-only, physically administered, E2EE with complete sharing, and
deployable on a hardened single-host Debian box with encrypted backups.

**Architecture:** The trust boundary is already correct (server stores only
ciphertext + filenames; client owns all confidentiality crypto; Rust `keycore`
owns all private-key ops). This plan does NOT re-architect that boundary. It
(1) closes correctness/security/crypto defects found in review, (2) builds the
test + verification tier that currently does not exist, (3) finishes the E2EE
feature model (public/owner key delivery, enrollment), (4) cleans the plumbing,
(5) does measured performance work, then (6) builds the OS/network/backup
hardening that lives outside today's repo.

**Tech Stack:** Python 3.11+ (Quart/ASGI, httpx, Click, argon2-cffi, cbor2,
PyNaCl), Rust (PyO3, dalek, chacha20poly1305, argon2, hkdf), SQLite (WAL),
WireGuard, nftables, systemd, AppArmor, LUKS2.

---

## How to read this plan

- Findings from the four review passes are consolidated in the table below with
  stable IDs (`SEC-*`, `CRY-*`, `PERF-*`, `ARCH-*`). Every work item references
  the finding(s) it closes.
- **Hard-stop flags** mark items that, per the project's CLAUDE.md, MUST get
  explicit human approval before execution:
  - `[APPROVAL: deps]` — adds/removes/changes a dependency.
  - `[APPROVAL: delete]` — deletes/renames/moves a file.
  - `[APPROVAL: api]` — changes a public API, wire format, DB schema, or CLI.
  - `[APPROVAL: tests]` — modifies an existing test file (new test files are fine).
  - `[APPROVAL: durability]` — changes a crash-durability guarantee.
- **Invariants that must never regress** (carry into every task):
  - Server never sees plaintext, file keys, or unwrapped symmetric keys.
  - Decryption is fail-closed and atomic; no partial plaintext is ever exposed.
  - No custom crypto primitives; rely on audited libraries.
  - All error paths stay generic (no username/file enumeration oracles).
  - Randomness aborts on OS entropy failure.
  - **Peer identity is `request.remote_addr` only; NO forwarded-header /
    ProxyFix middleware may ever be registered** (it would make peer-binding +
    rate limiting spoofable). Enforce with a startup assertion + a CI test.
  - **The server runs as a single worker** (the authoritative rate limiter and
    the SQLite connection model are per-process); a startup check must fail
    closed if more than one worker is configured, unless/until the limiter is
    moved to shared state. (SEC-M3)
  - Constant-time / timing-equalized paths (login, share, unshare) stay
    input-independent — any dedup of that code must be proven timing-stable.
  - Every code change keeps `pytest` + `cargo test` green and adds tests
    alongside (TDD).

> **Plan revision note (post-review):** This plan was reviewed by four
> specialists (security, crypto, performance, plan-quality). Their corrections
> are folded in below — notably the CRY-H1 rationale/test (Task 0.1), the
> Phase 2↔3 file-collision ordering, the 1A/1B ordering, the Phase 4
> connection/fsync/index corrections, the Phase 2 design-vs-impl split, and the
> "Accepted limitations" section. Items marked **(rev)** were changed by review.

---

## Current state assessment

The application core is implemented and green: **86 Python + 22 Rust tests pass**,
`keycore` builds. The system already does per-file E2EE (XChaCha20-Poly1305,
192-bit random nonces, 4 MiB chunks, AAD chunk binding, BLAKE2b Merkle tree with
an Ed25519-signed root, fail-closed atomic decryption), per-recipient key
wrapping with ephemeral-static ECDH (forward secrecy), an Argon2id-encrypted
key store with mlock/zeroize, a Quart server with chunked upload/atomic finalize/
ciphertext-only download/transactional quota/visibility policy, timing-equalized
auth and share endpoints, and a physical-console admin CLI.

What is missing for the "final product": (a) the OS/network/backup hardening
(WireGuard, nftables, AppArmor, systemd sandboxing, LUKS, scheduled uptime,
kill-switch, encrypted backups) — none of it is in the repo; (b) parts of the
sharing model (public on-demand wrapping, owner-keys-to-self, pubkey enrollment);
(c) the test/verification tier (no route-level integration tests, no fuzz/
property tests despite the spec mandating them); plus the defects below.

### Consolidated review findings

| ID | Sev | Area | Summary | Phase |
|----|-----|------|---------|-------|
| SEC-H1 / ARCH-M7 | HIGH | supply chain | Installed cbor2 6.1.1, argon2-cffi 25.1.0, pytest 9.0.3, pytest-asyncio 1.3.0 exceed pyproject upper bounds; no application lockfile; pip-audit/cargo-audit not in CI. The attacker-facing CBOR parser runs an untested major version. | 0 |
| CRY-H1 | HIGH | crypto | Ed25519 uses `verify()` not `verify_strict()` (`rust/keycore/src/signing.rs:45`). **(rev)** With `legacy_compatibility` off, scalar non-canonicality (S≥L) is already rejected; the real gap is the missing small-order-R / low-order-pubkey check. Fix still warranted. | 0 |
| CRY-M1 / ARCH-L5 | MED | crypto | `total_chunks`/`chunk_index` packed as u32 in `ChunkAAD` (`shared/models.py:383`) but u64 in the signed input (`models.py:131`); only the `MAX_CHUNKS=2²⁰` cap prevents a width-confusion gap. | 0 |
| CRY-M3 / ARCH-M6 | MED | crypto | Download path never asserts `header.chunk_size == CHUNK_SIZE`; accepts up to 16 MiB (`client/encryptor.py:317`); `MAX_CHUNKS` vs `MAX_CHUNKS_PER_FILE` alias hides which ceiling applies (`server/storage.py:38`). | 0 |
| SEC-M1 | MED | filesystem | Blob/staging chunk read (`send_file`) and write (`mkstemp`) don't use `O_NOFOLLOW`; `_safe_path` resolves symlinks for the containment decision (`server/storage.py:186,773,1187`). | 0 |
| CRY-M2 | MED | crypto | metadata/chunk domain separation depends on `file_key != meta_key`, undefended by assertion (`client/encryptor.py:134-135`). | 0 |
| CRY-L3 | LOW | crypto | `mlock` failure is a stderr warning, process continues with swappable keys (`identity.rs:189`). | 0/5 |
| CRY-I1 | INFO | docs | `original_size` stored exact, not "padded" (doc fixed in README; fix field comment `models.py:404`). | 0 |
| CRY-I2 | INFO | crypto | metadata blob is unsigned / not bound to file version. | 2 |
| ARCH-H1 | HIGH | testing | Zero route-level integration tests; the whole request surface is untested end-to-end. | 1 |
| ARCH-H2 | HIGH | architecture | Module-global singletons + dynamic `request.user_id` defeat typing (40 `# type: ignore` in storage.py) and block integration testing. | 1 |
| SEC-GAP / CRY-GAP | HIGH | testing | No fuzz/property tests; `hypothesis` declared but unused; spec mandates parser fuzzing + nonce-uniqueness/key-isolation property tests. | 1 |
| FEAT-2 / SEC-GAP / ARCH-M8 | HIGH | feature | Public-visibility on-demand wrapping not implemented; owner self-access uses a plaintext `<file_id>.keys.json` cache instead of keys wrapped to the owner's identity. | 2 |
| FEAT-1 | MED | feature | Recipient pubkey discovery is out-of-band; only Ed25519 keys are stored server-side (not X25519); enrollment is manual. | 2 |
| ARCH-H3 | HIGH | cleanliness | `upload_finalize` is a 225-line god-function (`server/storage.py:430-655`); `cli.upload`/`cli.download` similar. | 3 |
| ARCH-H4 | HIGH | cleanliness | Dead code: `merkle_proof`/`verify_merkle_proof`, entire `client/sharing.py`, `get_session_version`, `get_user_by_id`, `get_file_shares`, unused exceptions. | 3 |
| ARCH-M1..M5 | MED | cleanliness | Duplicated `_canonicalize_username` (diverged), copy-pasted timing-equalization, two response checkers, "Bearer None" header bug, file_id validation in 3 places. | 3 |
| PERF-H1 | HIGH | perf | Global `RLock` + single connection serializes ALL reads; WAL concurrency unrealized (`server/database.py:196`). | 4 |
| PERF-H2 | HIGH | perf | One `fsync` per uploaded chunk (`storage.py:1189`); O(total_chunks) flushes. | 4 |
| PERF-M5 | MED | perf | Per-chunk quota check re-runs a SUM-with-JOIN → O(n²) per upload (`storage.py:400`, `database.py:771`). | 4 |
| PERF-M1/M2/M3/M4 | MED | perf | list_user_files temp B-trees; cleanup full scan; sequential download (no prefetch); orphan listdir every 60s. | 4 |
| PERF-H3 | HIGH* | perf | Argon2 login concurrency fixed at 4 (intentional); make RAM-relative + configurable. | 4 |
| SEC-M2 | MED | security | Peer identity = `request.remote_addr` with no proxy/NAT guard (`auth.py:423`). **(rev: invariant promoted to 0)** | 0/5 |
| SEC-M3 | MED | security | In-memory rate limiter is per-process/per-worker and reset on restart. **(rev: single-worker check promoted to 0)** | 0/5 |
| SEC-M4 | MED | security | `login_attempts` row growth under username flood (`database.py:421`). **(rev: promoted to 0)** | 0 |
| SEC-L1..L4, ARCH-L1..L6, PERF-L1/L2, CRY-L1/L2 | LOW | misc | Self-share no-op, client error-type leak, filename denylist rot, cleanup jitter, comment narration, Visibility magic ints, padding ValueError, db fixture dup, rate-limiter sort, unused-merkle verifier weakness, documented local timing oracle. | 3/4 |

\* PERF-H3 is "high impact, intentional"; treat as a tuning knob, not a bug.

---

## Target state (from README PART II) and the gap

| Target capability (PART II) | Status | Closed by |
|---|---|---|
| Per-file E2EE, forward secrecy, signed Merkle root, fail-closed decrypt | DONE | — |
| Per-recipient key wrapping (ephemeral-static ECDH) | DONE | — |
| Argon2id key store, mlock/zeroize, no core dumps | DONE (mlock soft-fail) | Phase 0/5 |
| Server policy enforcement without plaintext access | DONE | — |
| Chunked authenticated upload/download, ciphertext quota | DONE | — |
| Operator account/quota/session admin (console-only) | DONE | — |
| Public on-demand per-user wrapping; owner keys wrapped to owner | PARTIAL | Phase 2 |
| Recipient pubkey enrollment/discovery | MANUAL | Phase 2 |
| Parser fuzzing + crypto property tests | MISSING | Phase 1 |
| WireGuard transport (key pinning, peer allowlist) | MISSING | Phase 5 |
| nftables default-deny + WG-only + rate limit | MISSING | Phase 5 |
| systemd services/timers, scheduled uptime, kill-switch | MISSING | Phase 5 |
| AppArmor + systemd sandboxing, separate service users | MISSING | Phase 5 |
| Minimal Debian + LUKS2 encrypted LVM provisioning | MISSING | Phase 5 |
| Minimal security logging policy | MISSING | Phase 5 |
| Encrypted internal-HDD backup flow | MISSING | Phase 6 |

---

## Phase 0 — Correctness & safety quick wins (low risk, high value)

> **✅ EXECUTED 2026-05-29** — commits `1ca93f0..9448bb8`. All tasks landed;
> **120 Python + 24 Rust tests green**; pyright/black/isort/ruff clean; pip-audit
> ("no known vulnerabilities") + cargo audit (75 crates, 0 advisories) clean.
> Deviations from the written plan: 0.2 kept non-breaking (option b, no wire
> change); **0.3 chunk_size gate pins to `self.chunk_size`** (which equals the
> module `CHUNK_SIZE` for every production caller — no production code builds a
> non-default `FileEncryptor` — so no pre-existing test had to be modified);
> **0.4 read path** uses an `O_NOFOLLOW` fd + plain `Response` (the installed
> Quart `send_file` cannot accept an fd), which also fixed a latent
> `etag=`-on-`send_file` `TypeError` in the chunk-download path; `requirements.txt`
> deleted and `target/` untracked (both approved); application lockfile deferred
> to Phase 7. 0.6d: tool targets `py311` vs the 3.13 runtime is correct — no change.

**Objective:** Close the cheap, high-confidence defects with no architectural
change. Everything here is small, locally testable, and unblocks trust in the
rest of the work. Each item ships with a regression test.

**Files:** `rust/keycore/src/signing.rs`, `shared/models.py`,
`client/encryptor.py`, `server/storage.py`, `pyproject.toml`, `requirements.txt`,
new tests under `tests/` and `rust/keycore/src/*` `#[cfg(test)]`.

### Task 0.1 — Ed25519 strict verification (CRY-H1) **(rev)**

**Corrected rationale (post-review):** ed25519-dalek 2.2.0 is built here WITHOUT
`legacy_compatibility` (confirmed via `cargo tree -e features`), so the
non-strict `verify()` ALREADY rejects non-canonical / unreduced `S` (S ≥ L) —
there is no scalar-malleability gap. The ONLY delta `verify_strict()` adds is
the **small-order-R / low-order public-key rejection** (and the cofactorless
group equation). The fix is still correct and worth doing; but the test must
target small-order R, NOT an `S ≥ L` vector (which both `verify` and
`verify_strict` reject — an `S ≥ L` test is a false-green and proves nothing).

- [ ] Write a failing Rust test in `signing.rs` `#[cfg(test)]` using a signature
      whose `R` is a small-order point (or a low-order public key) — a vector
      that current `verify()` accepts but `verify_strict()` rejects. Source the
      vector from the `ed25519`/dalek test corpus rather than hand-rolling; if no
      robust in-repo vector can be built against this dalek version, document
      that and assert the property via the corpus vector. Assert current
      behavior accepts and target behavior rejects.
- [ ] Run `cargo test signing` → expect the new test to FAIL under `verify`.
- [ ] Change `signing.rs:45` `verifying_key.verify(message, &signature)` →
      `verifying_key.verify_strict(message, &signature)`.
- [ ] Run `cargo test` → expect PASS (all 22 + new). Re-run the Python
      `tests/test_encryptor.py` signature tests via `pytest` (after `maturin
      develop --release`) to confirm legitimate signatures STILL verify (dalek's
      `SigningKey::sign` never emits small-order R, so no regression — assert
      this explicitly, including a round-trip over a previously-stored header).
- [ ] Commit.

### Task 0.2 — AAD width hardening (CRY-M1, ARCH-L5)

- [ ] Add a Python test asserting the invariant `MAX_CHUNKS < 0xFFFFFFFF` AND
      that `ChunkAAD` round-trips the full `total_chunks` range without aliasing.
- [ ] Decide one of: (a) widen `ChunkAAD.serialize` packing of `chunk_index`
      and `total_chunks` to u64 (`">16sQHQ"`) [APPROVAL: api — changes AAD wire
      bytes, a breaking format change → bump `PROTOCOL_VERSION`], OR (b) keep u32
      and add an explicit module-level assertion + comment at `ChunkAAD` binding
      the invariant `MAX_CHUNKS < 2³²` and `METADATA_CHUNK_INDEX (0xFFFFFFFF) >
      MAX_CHUNKS`. Recommended for Phase 0: (b) (non-breaking); schedule (a) for
      the next protocol-version bump.
- [ ] Implement, run `pytest tests/test_models.py -v` → PASS. Commit.

### Task 0.3 — Download geometry assertions (CRY-M3, ARCH-M6)

- [ ] Add a test: a header with `chunk_size != CHUNK_SIZE` or `total_chunks >
      MAX_CHUNKS_PER_FILE` is rejected by `decrypt_file` with `CryptoError`/
      `DecryptionError` before any chunk is written.
- [ ] In `client/encryptor.py` after header validation (~line 277), add
      `if header.chunk_size != CHUNK_SIZE: raise CryptoError(...)` (assert
      against the module **constant**, the on-wire invariant — NOT
      `self.chunk_size`, which is a configurable instance attr and would reject
      legitimately-produced files) and
      `if header.total_chunks > MAX_CHUNKS_PER_FILE: raise CryptoError(...)`.
      First confirm no caller constructs `FileEncryptor(chunk_size=...)` with a
      non-default value. **(rev)**
- [ ] Stop the confusing import alias at `server/storage.py:38`
      (`MAX_CHUNKS_PER_FILE as _MAX_CHUNKS`) AND at `client/encryptor.py:78`
      (`MAX_CHUNKS: int = MAX_CHUNKS_PER_FILE`) — import/use under the real name
      in both. **(rev)**
- [ ] Run `pytest tests/test_encryptor.py -v` → PASS. Commit.

### Task 0.4 — O_NOFOLLOW on blob/staging data paths (SEC-M1)

- [ ] Add a test (server-side, using `tmp_path`) that a symlink planted at a
      chunk path is not followed on read or write.
- [ ] In `_write_file_bytes` (`storage.py:1172`) open the temp file with
      `os.open(..., O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0o600)` instead of bare
      `mkstemp` semantics where a symlink could be followed (mkstemp already
      O_EXCL-creates a fresh name, so the real gap is the *final* path and the
      parent dir; reject any path component that is a symlink in `_safe_path`).
- [ ] For reads, open with `os.open(chunk_path, O_RDONLY|O_NOFOLLOW)` and pass
      the fd to `send_file`.
- [ ] Run `pytest tests/ -k storage` → PASS. Commit.

### Task 0.5 — Key-independence + doc/comment fixes (CRY-M2, CRY-I1, CRY-L3 doc)

- [ ] Add `assert file_key != meta_key` after key generation in
      `encrypt_file` (`encryptor.py:134-135`). **(rev)** Comment must state the
      truth: metadata/chunk separation rests on the **distinct AAD** (metadata
      sentinel `chunk_index=0xFFFFFFFF, total_chunks=0`) AND **independent random
      keys**; this assertion is only a catastrophic-RNG-failure tripwire, NOT the
      domain-separation mechanism (don't overstate it).
- [ ] Fix the misleading comment at `models.py:404` (`# Padded — not exact`) to
      "exact plaintext size; encrypted in the blob, never sent in clear."
- [ ] Add a comment at `identity.rs` mlock sites noting failure is non-fatal and
      that production hardening (Phase 5) must guarantee `RLIMIT_MEMLOCK`.
- [ ] Run full `pytest` → PASS. Commit.

### Task 0.6 — Dependency reconciliation + supply-chain gate (SEC-H1, ARCH-M7) `[APPROVAL: deps]`

- [ ] Run `pip-audit` (install in the dev env first) and `cd rust/keycore &&
      cargo audit`; record output. (Crypto agent already confirmed `cargo audit`
      clean; `pip-audit` was not installed.)
- [ ] Re-run the full suite against the actually-installed versions; if green,
      raise the pyproject upper bounds to admit the audited lines (cbor2 6.x,
      argon2-cffi 25.x, pytest 9.x, pytest-asyncio 1.x) — OR pin to the exact
      tested versions. This is an explicit dependency decision → get approval.
- [ ] Decide `requirements.txt` fate `[APPROVAL: delete]`: delete it (pyproject
      is sole source of truth) or generate it from a lock.
- [ ] Add an application lockfile (`pip-compile`/`uv lock`) `[APPROVAL: deps]`.
- [ ] Reconcile `requires-python`/tool targets with the runtime (declared 3.11,
      running 3.13): either pin the interpreter or bump targets after testing.
- [ ] Commit.

> **Task 0.6 sub-split (rev):** treat as four separately-approvable items —
> 0.6a audit + version-bound reconciliation `[APPROVAL: deps]`; 0.6b
> `requirements.txt` fate `[APPROVAL: delete]`; 0.6c lockfile `[APPROVAL: deps]`;
> 0.6d interpreter/target reconciliation (3.11 target vs 3.13 runtime) — flag as
> its own decision, a target bump can change typing/lint behavior.

### Task 0.7 — Promote network-independent rate-limit hardening (SEC-M4, SEC-M2) **(rev)**

Promoted from Phase 5 by the security review: these are pure server-side
defenses with no infrastructure dependency, and Phase 2 widens the authenticated
surface before Phase 5 lands.

- [ ] **SEC-M4:** add a per-(peer,username) cap on `login_attempts` inserts so a
      single peer cannot author thousands of rows/min across synthetic usernames
      (`database.py:421` `record_login_attempt`). Add a regression test that a
      flood of distinct usernames from one peer is bounded.
- [ ] **SEC-M2 invariant:** add a startup assertion + a CI test that NO
      forwarded-header / ProxyFix middleware is registered and that
      `_get_peer_identity` uses `request.remote_addr` unmodified (`auth.py:423`).
- [ ] **SEC-M3 decision:** add a startup check that fails closed if more than one
      worker is configured (single-worker is the committed model — see
      Invariants), OR open a tracked task to move the composite limiter to shared
      state. Document the chosen path in the systemd unit (Phase 5).
- [ ] Run full `pytest` → PASS. Commit.

**Phase 0 acceptance:** all existing + new tests green; `verify_strict` in place
with a **small-order-R** regression test (not S≥L); download rejects bad geometry
against the `CHUNK_SIZE` constant; symlink test passes; `pip-audit` + `cargo
audit` clean and wired into the dev workflow; dependency declarations match the
tested environment; the forwarded-header ban and single-worker check are enforced
at startup and covered by tests; per-peer attempt-row flood is bounded.

---

## Phase 1 — Testability & verification tier (unblocks safe change)

> **✅ EXECUTED 2026-05-30** — commits `c98d3b8..09a8db7`. **238 Python + 27 Rust
> tests green**; full toolchain clean (black, isort, ruff, pylint ≥9.8, pyright
> 0-errors, cargo fmt, clippy `-D warnings`, pip-audit, cargo audit) and wired into
> a committed GitHub Actions CI (1D). Order followed 1B-smoke → 1A → 1B-full/1C/1D.
> 1A landed the typed `AppState` + `g.identity`, dropping storage.py `# type: ignore`
> 40→0 — reviewed behavior-preserving. 1B added the full route-integration suite;
> 1C added hypothesis property/fuzz tests (pad round-trip, parser-never-crashes incl.
> the depth-64 recursion guard, nonce uniqueness, key isolation, fail-on-corruption,
> AAD-binding) + Rust nonce-uniqueness tests. **The integration suite surfaced and we
> fixed a blocking production bug** — `upload_init` keyed staging on a hyphenated
> `upload_id` while `_validate_id` canonicalized to hyphen-free hex, so no upload
> could ever complete (commit `560d8f9`). pyright now uses the venv; remaining
> false positives (keycore native ext, click group) carry targeted suppressions;
> pylint complexity checks are deferred to Phase 3 (ARCH-H3) with annotations.

**Objective:** Build the test infrastructure that lets every later phase refactor
and extend safely. This is the prerequisite for Phases 2–4.

> **Ordering (rev):** Workstream **1B's smoke-test subset lands BEFORE 1A**. 1A is
> a behavior-risky change to global state; do it under at least a smoke layer of
> integration tests, not before. The body previously listed 1A first — execute
> 1B-smoke → 1A → 1B-full. This resolves the contradiction the risk register
> already flagged.

### Workstream 1A — App-context refactor (ARCH-H2) `[APPROVAL: api — internal wiring; see risk register: Med/High impact]` (depends on 1B-smoke)

- Replace module-global singletons (`server/auth.py:388-392`,
  `server/storage.py:126-130`) and the `init_*()` mutation pattern with a typed
  `AppState` dataclass (db, blob_dir, staging_dir, session_secret, limits) stored
  on `app.extensions["localcloud"]`, accessed via `current_app` in handlers.
- Replace dynamic `request.user_id`/`request.username` with a typed object stored
  on Quart's `g`. Target: eliminate the bulk of the 40 `# type: ignore` in
  storage.py.
- Acceptance: `pyright` clean on `server/` with far fewer ignores; behavior
  unchanged (Phase-0 tests still green). Needs its own detailed plan.

### Workstream 1B — Route-level integration tests (ARCH-H1, ARCH-L6)

- Add `conftest.py` fixtures `app` and `client` (Quart `app.test_client()`) over
  a `tmp_data_dir` DB and a test session secret; lift the duplicated `db` fixture
  (`test_database.py:22`, `test_storage_share.py:19`, `test_admin.py:38`) into
  conftest.
- New `tests/test_api_*.py` covering: login (success/failure/rate-limit/peer
  binding), the full upload init→chunk→finalize state machine, download +
  metadata + owner_pubkey, delete idempotency, list pagination + total_bytes
  suppression, share/unshare visibility transitions, wrapped_keys, quota, and the
  `require_auth` middleware (session_version revocation, disabled user).
- Acceptance: every server route exercised end-to-end; coverage report shows the
  request surface covered.

### Workstream 1C — Fuzz & property tests (SEC-GAP, CRY-GAP; spec §10)

- Use the already-declared `hypothesis` to property-test: `pad_to_size_class`/
  `unpad` round-trip on arbitrary bytes; `_safe_cbor_loads`/`FileHeader.deserialize`/
  `MetadataBlob.deserialize` never crash and only raise `MalformedRequestError`
  on arbitrary/oversized/tagged input; nonce uniqueness across many
  `encrypt_file` runs; key isolation (distinct files → distinct keys); fail-on-
  corruption (flip any byte → decrypt raises).
- **(rev)** Add an **AAD-binding** property: flipping ANY AAD-relevant field
  (`file_id`, `chunk_index`, `total_chunks`, version, the metadata sentinel)
  makes `decrypt_chunk`/metadata-decrypt fail — directly guards CRY-M1/M2 and the
  sentinel.
- **(rev)** Add nonce-uniqueness property tests for the **wrap** path
  (`wrapping.rs` ephemeral pub + nonce) and the **key store** nonce, not just
  file chunks — these are Rust, so add `#[cfg(test)]`/proptest there.
- Add a parser fuzz target (atheris or hypothesis-based) for the CBOR/header
  decoders. `[APPROVAL: deps]` if atheris is chosen.
- Acceptance: property suite green in CI; documented coverage of the spec's
  "nonce uniqueness, key isolation, failure on corruption" mandate, plus
  AAD-binding and wrap/keystore nonce uniqueness.

### Workstream 1D — CI pipeline

- CI runs `black --check`, `isort --check`, `ruff check`, `pylint`, `pyright`,
  `pytest`, then `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`,
  `cargo audit`, `pip-audit`. Gate merges on green.
- Acceptance: pipeline file committed; one green run.

**Phase 1 acceptance:** integration + property/fuzz tiers exist and pass in CI;
type-ignore count materially reduced; later phases can refactor under test.

---

## Phase 2 — Complete the E2EE feature model (close README §5.4) `[APPROVAL: api]`

**Objective:** Make sharing/visibility match the spec and remove the plaintext
owner key cache.

> **Split into 2-design then 2-impl (rev).** Phase 2 contains unresolved protocol
> design (2B model choice, 2C key-authenticity binding). **Phase 2-design is a
> blocking deliverable**: produce a public-wrapping decision doc + a security
> re-review, and answer the "must-resolve" questions below, BEFORE any 2-impl
> work is scheduled or estimated. Do not place 2-impl on the milestone timeline
> until 2-design closes. 2-impl must also run on `storage.py`/`cli.py` BEFORE
> Phase 3's refactor of those same files (see Sequencing).
>
> **Must-resolve before 2-impl (from crypto + security review):**
> - **2B model:** recommended baseline is **(iii) per-recipient wrap to every
>   enrolled user at publish time** — it reuses the audited `wrapping.rs` path
>   unchanged, caches nothing new, stays fail-closed, and sidesteps the
>   key-commitment problem. Model (ii) request/grant is unsound for an offline
>   owner (forces server-side plaintext keys or cached bundles). Any
>   multi/anonymous-recipient variant (i) MUST add a key-commitment construction
>   (XChaCha20-Poly1305 is not key-committing → partitioning-oracle risk) and a
>   separate `...-public-v1` wrap domain, and must bound wrap fan-out/requests
>   (DoS). (CRY-H2/H3, SEC-M3-public)
> - **2C key authenticity:** the recipient's X25519 MUST be **self-signed by
>   their Ed25519** at enrollment and verified by the sharer before wrapping, so
>   pinning the Ed25519 fingerprint out-of-band transitively authenticates the
>   X25519 (the wrap binds only the *sender's* Ed25519 today, not the
>   recipient's X25519 ↔ identity). The directory lookup must return a uniform
>   response for unknown-vs-keyless users (no enumeration oracle). (CRY-H4, SEC-H3)

### Task 2A — Wrap owner keys to the owner's own identity (ARCH-M8, SEC-GAP)

- Spike: on upload, wrap `file_key`+`meta_key` to the owner's own X25519 key and
  store the bundle server-side (a self-share row), so `get_wrapped_keys` returns
  a bundle for the owner too. Removes the on-disk `<file_id>.keys.json` plaintext
  cache and collapses download/share into a single key path.
- Implement client + server; migrate/retire the cache; ensure `rm` has no
  dangling key artifacts.
- Acceptance: owner downloads/shares with no local plaintext key file; one
  unified key-acquisition path in `cli.download`/`cli.share`.

### Task 2B — Public-visibility key delivery (SEC-GAP, spec §5.3/5.4)

- Spike (genuine design question): the spec says "client generates wrapped keys
  on demand per user" for public files, but the owner may be offline. Choose a
  model: (i) owner pre-wraps to a public/anonymous scheme, or (ii) a request/grant
  flow, or (iii) accept that "public" means "shared to all enrolled users" via
  per-user wrapping at share time. Document the leakage trade-offs ("no server-
  side caching of wrapped keys" constraint).
- Implement the chosen model; keep it fail-closed (today a non-owner with no
  share row correctly cannot decrypt).
- Acceptance: an authenticated non-owner can decrypt a public file per the chosen
  model; no server-side plaintext key caching.

### Task 2C — Pubkey enrollment & directory (FEAT-1) `[APPROVAL: api — schema v6]`

- Store the user's X25519 key server-side alongside the existing Ed25519 key
  (`users` schema migration → v6) **plus an Ed25519 self-signature over the
  X25519 key** (rev), and serve both for share targeting; provide a lookup so
  `share` no longer needs `--recipient-pubkey` out-of-band.
- The sharer MUST verify the self-signature before wrapping; the server stays
  untrusted for key authenticity, and pinning the Ed25519 fingerprint
  out-of-band transitively authenticates the X25519. (rev)
- The lookup MUST return a uniform response for unknown-vs-keyless users (no
  enumeration oracle — matches the rest of the system). (rev)
- Acceptance: `share <file> <user>` resolves + verifies the recipient key via the
  server; a server-substituted X25519 is rejected by the self-signature check;
  fingerprint-pinning path documented.

### Task 2D — Bind metadata to file version (CRY-I2) `[APPROVAL: api — wire change]` **(rev)**

- Include **`merkle_root` only** (NOT the signature — it already covers the root)
  in the metadata AAD so the encrypted metadata blob is pinned to one file
  version. This is a wire-format change to the metadata blob: bump the metadata
  AAD domain tag + `PROTOCOL_VERSION` and gate behind a migration, exactly like
  the 0.2(a) AAD change.
- Invariant to record: the metadata AAD may depend on `merkle_root`, but the
  Merkle tree must NEVER depend on the metadata ciphertext (no circular
  dependency). Encrypt order today (root computed before metadata sealed) already
  satisfies this — keep it.
- Acceptance: a swapped historical metadata blob fails to decrypt against current
  chunks; existing-file decrypt handled by the version bump/migration.

**Phase 2 acceptance:** private/shared/public/owner all decrypt through one
coherent, fail-closed key path; no plaintext keys at rest; enrollment works;
metadata is version-bound. Each sub-task needs its own detailed plan.

---

## Phase 3 — Architecture & cleanliness (under test from Phase 1)

**Objective:** Reduce maintenance cost and the surface area each future audit
must re-read. Pure restructuring — no behavior change; tests must stay green.

> **Ordering (rev):** Tasks 3A and 3B touch `storage.py`/`cli.py`/`api_client.py`
> — the SAME files Phase 2 rewrites. **3A/3B must run AFTER Phase 2-impl lands**,
> not in parallel with it (the Sequencing diagram is corrected accordingly). 3C
> (dead code) and 3D (policy/exceptions/comments) are file-disjoint from Phase 2
> and may run in parallel.

- **Task 3A (ARCH-H3):** Decompose `upload_finalize` into
  `_validate_finalize_request`, `_verify_staged_chunks`, `_commit_finalized_blob`;
  same for `cli.upload`/`cli.download`.
- **Task 3B (ARCH-M1..M5)** `[APPROVAL: tests; api — import paths]` **(rev)**:
  Single `canonicalize_username` and `canonicalize_file_id` in `shared/`, used by
  client+server; single status→exception mapper in `api_client.py`; one
  `constant_deadline` helper + one timing-budget constant for auth/share/unshare;
  fix the `"Bearer None"` header. NOTE: `tests/test_auth_token.py` and
  `server/storage.py` import `_canonicalize_username` from `server.auth` — either
  keep a re-export shim at the old path (no import changes) or update the test
  (a test-file change → approval). The dedup of the timing-equalization code MUST
  ship with a test proving the equalized endpoints stay input-independent in
  timing (no reintroduced enumeration oracle). (CRY/SEC review)
- **Task 3C (ARCH-H4)** `[APPROVAL: delete]`: Remove dead code — entire
  `client/sharing.py`, `get_session_version`, `get_user_by_id`,
  `get_file_shares`, unused exceptions (`NonceReuseError`, `FileNotFoundError_`,
  `UploadError`). **(rev)** Decide `merkle_proof`/`verify_merkle_proof`
  explicitly via the Accepted-Limitations decision on range proofs (do NOT leave
  it conditional on Phase 4E, which does not wire range proofs): if range proofs
  are out of scope, DELETE them; if ever wired, they need their own audit +
  property tests first (CRY-L1).
- **Task 3D (ARCH-L1..L4, SEC-L1/L2/L3):** Move review-round IDs from inline
  comments to git history; reference `Visibility` enum instead of SQL magic ints;
  raise typed exceptions from padding; collapse the filename denylist into the
  category check; make self-share a real no-op or explicit success; drop the
  client exception-type print.
- Acceptance (rev — measurable): behavior identical (Phase 0/1 tests green);
  `≤ 5 # type: ignore` in `storage.py` (baseline 40); `upload_finalize ≤ 60`
  lines and no function in `storage.py` > 80 lines; `vulture`/`pylint` report no
  unused symbols.

---

## Phase 4 — Performance (measure first, always)

**Objective:** Remove the concurrency ceilings. **Every task: capture a baseline
benchmark, change one thing, re-measure, document the delta.** No optimization
without a profile.

- **Task 4A (PERF-H1) — read connections:** Give reads their own connection(s)
  (read-only pool or per-thread connections) so WAL concurrency is realized; keep
  the write lock for the single writer. **(rev) Two correctness prerequisites the
  RLock currently provides and separate connections must replace:** (1) EVERY new
  connection must replicate the full PRAGMA init — `journal_mode=WAL`,
  `foreign_keys=ON` (SQLite defaults FK enforcement OFF per-connection!),
  `busy_timeout=5000` — or FKs silently disable and readers hit `SQLITE_BUSY`
  during checkpoints; (2) enumerate every read method and classify
  single-statement (safe on a pooled autocommit conn) vs. multi-statement
  sequences that need an explicit read transaction for snapshot consistency. The
  RLock guarded more than torn single reads. Baseline: `py-spy` under concurrent
  downloads showing `RLock.acquire` frames; target: those frames collapse with
  no FK/consistency regression (full suite green).
- **Task 4B (PERF-H2) — fsync strategy** `[APPROVAL: durability]` **(rev: split):**
  - **4B-a:** `PRAGMA synchronous=NORMAL` (safe under WAL — on power loss you may
    lose the last txn but the DB is not corrupted). Low risk; do it.
  - **4B-b:** dropping the per-chunk `os.fsync` (`storage.py:1189`) is RISKIER
    than the plan first stated: finalize compares the *recorded* `chunk_hash`
    string against the client's `expected_hashes` — it does NOT re-read and
    re-hash the bytes from disk. So a chunk silently truncated by a crash (after
    `os.replace`, before flush) keeps its correct recorded hash, finalize passes,
    and a corrupt blob is committed (caught only later by the client's
    fail-closed download Merkle check). To drop per-chunk fsync safely, EITHER
    keep a single directory `fsync` at finalize AND have finalize re-hash bytes
    from disk, OR keep per-chunk fsync. Document the exact failure mode before
    approval. Measure fsync count with `strace -c -e fsync`.
- **Task 4C (PERF-M5) — quota counter:** Maintain a running staging-bytes total
  (column on `staging_uploads`, updated in the same `BEGIN IMMEDIATE` as the
  chunk insert) to replace the per-chunk O(n) SUM-with-JOIN. Preserve the
  race-free transactional guarantee; add a concurrency regression test.
- **Task 4D (PERF-M1/M2/M4) — query/scan fixes (rev — re-scoped):**
  - `list_user_files`: the per-branch indexes the original plan wanted to "add"
    ALREADY exist (migration v5: `idx_files_owner`, `idx_file_shares_user`,
    `idx_files_visibility(visibility, created_at DESC)`). The real win is to drop
    the two TEMP B-trees (`UNION` dedup + full-set `ORDER BY`): use `UNION ALL`
    with explicit de-dup only where owner∩shared∩public can overlap, and push
    `ORDER BY created_at DESC LIMIT` into the public branch (its index is already
    ordered). Baseline/measure: `EXPLAIN QUERY PLAN` before/after + timing at
    realistic public-corpus size.
  - `cleanup_expired_staging`: an index alone WON'T be used — the `OR` predicate
    defeats it (confirmed: still `SCAN`). Restructure the predicate (e.g.
    `expires_at < max(now, grace)` filtered by `finalizing`, or a `UNION` of two
    index-friendly arms) THEN index `expires_at`. (Tiny table at single-user
    scale — measure before bothering.)
  - Orphan scan: `os.scandir` (lazy, `is_dir()` without extra stat) + a longer
    interval than the 60 s expiry sweep.
- **Task 4E (PERF-M3) — download prefetch:** Bounded look-ahead window feeding the
  streaming decrypter, re-ordered to sequential before write (AAD/Merkle are
  order-sensitive). **(rev)** Bound the window by BYTES (e.g. 4–8 chunks =
  16–32 MiB), not by the 16-connection pool count, and state the memory ceiling.
  FIRST measure the sequential baseline's CPU-vs-network split (`py-spy` on the
  client during a large download): if network-bound, prefetch helps; if the
  single decrypt thread saturates, the complexity isn't justified.
- **Task 4F (PERF-H3) — Argon2 knob:** Make `_MAX_CONCURRENT_ARGON2` configurable
  and default it to `min(RAM_budget/128MiB, CPU-derived)`; never lower the Argon2
  cost. **(rev)** This is per-process — it is correct ONLY under the committed
  single-worker model (see Invariants); under N workers the effective Argon2
  memory is N× and would OOM. Measure p50/p95 login latency + peak RSS under
  concurrent logins.
- **Task 4G (rev — new) — SQLite operational tuning:** For a 24/7 box, set
  `wal_autocheckpoint` and consider a periodic `PRAGMA wal_checkpoint(TRUNCATE)`
  on the writer (a long-lived reader from 4A can otherwise let the `-wal` file
  grow unbounded — call this out as part of 4A's acceptance), decide
  `auto_vacuum=INCREMENTAL` vs periodic `VACUUM` (login_attempts + file churn
  fragment the DB), and size `cache_size` to box RAM. Measure DB file + `-wal`
  size over a soak test.
- Acceptance: a short `docs/benchmarks.md` with a NAMED baseline metric and
  re-measure for EVERY task (4C: large-upload wall-time + `EXPLAIN QUERY PLAN` of
  `get_total_staging_bytes`; 4D: `EXPLAIN QUERY PLAN`; 4F: login p50/p95 + RSS);
  no correctness regression (full suite + concurrency tests green).

---

## Phase 5 — Deployment & infrastructure hardening (bulk of README PART II §1–3, 8)

**Objective:** Build the hostile-box deployment. Delivered as version-controlled,
reproducible provisioning (scripts/Ansible) + docs, NOT manual steps. Most of
this is new `deploy/` content, not application code; it can proceed in parallel
with Phases 2–4 once Phase 0 lands.

- **WireGuard:** server keypair, client public-key allowlist, server-key pinning
  on the client, `wg0` config; bind the app to the WG interface; resolve SEC-M2
  by deriving peer identity safely (document "no forwarded-header middleware";
  ideally map WG pubkey→IP) and SEC-M3 (single-worker requirement OR move the
  rate limiter to shared/DB state for multi-worker durability) and SEC-M4 (cap
  per-peer attempt-row inserts).
- **nftables:** default-deny inbound; allow only the WireGuard UDP port; per-
  source rate limiting on that port pre-daemon.
- **systemd:** service units for the cloud daemon (run under Hypercorn) and the
  tunnel under **separate unprivileged users**; `LoadCredential=` for the session
  secret; scheduled-uptime timers that add/remove the firewall rule; an operator
  **kill-switch** script (drop the rule, kill sessions, stop services).
- **Sandboxing:** systemd `NoNewPrivileges`, `ProtectSystem=strict`,
  `ReadWritePaths=` only the data dir, `PrivateDevices`, `RestrictAddressFamilies`,
  read-only root + tmpfs writable paths; AppArmor profile confining the daemon to
  its dirs. Make `mlock` reliable here (RLIMIT_MEMLOCK) — closes CRY-L3.
- **(rev) Server-side secret hygiene (SEC-M2/secret):** the session HMAC secret
  and passwords live in plain Python `str` for the process lifetime and the
  server has no zeroization (unlike the Rust client). Mitigate at the process
  level: disable core dumps (`LimitCORE=0` / `PR_SET_DUMPABLE 0`), disable swap or
  `mlockall`, keep `LoadCredential=` for the secret, and document that Python
  `str` immutability makes true zeroization best-effort (so no-core-dump +
  no-swap + short secret lifetime are the real controls). A server core/swap leak
  of the HMAC secret enables token forgery for all users under the disk-snapshot
  threat model.
- **OS provisioning:** minimal Debian, LUKS2 + encrypted LVM, disable sleep/
  suspend, strip bluetooth/audio/camera/mic stacks, local-unlock-at-boot doc.
- **Logging:** minimal security-events-only policy (connections, auth failures,
  quota events, backup events), no plaintext metadata; journald config.
- Acceptance: from an external host, only the WG UDP port is reachable (nmap);
  AppArmor in enforce mode; rootfs read-only; kill-switch verified; scheduled
  uptime toggles reachability; a documented threat-test checklist passes.

---

## Phase 6 — Encrypted backup system (README PART II §7)

**Objective:** Internal-HDD, offline-by-default, LUKS2-encrypted backups holding
only ciphertext + encrypted metadata.

- Secondary LUKS2 partition, never auto-mounted; operator mount→snapshot/rsync→
  unmount script; verify only `blobs/`, `meta.db`, and encrypted metadata are
  copied (no plaintext ever); a tested restore procedure.
- Acceptance: a backup→wipe→restore drill reproduces a working server; backup
  media contains no plaintext (spot-checked).

---

## Phase 7 — Release hardening & operations

**Objective:** Make it shippable and operable.

- Supply chain: audits + SBOM in CI, reproducible `maturin --release` build,
  committed lockfiles, version/changelog discipline.
- Docs: threat model, runbooks (kill-switch, key rotation, user lifecycle,
  incident response, backup/restore), the "physical-console-only" operating
  procedure.
- **(rev) Key-rotation task (explicit):** document + TEST (a) session-secret
  rotation — confirm a rotated HMAC secret cleanly invalidates all outstanding
  tokens (it does by construction: HMAC mismatch) and the interaction with
  `session_version`; and (b) user identity-key (X25519/Ed25519) rotation and its
  effect on existing shares (recipients must be re-wrapped; old shares must be
  re-established). These are part of the audit checklist's tested key-rotation
  requirement.
- Final internal security review pass; recommend an external audit before any
  real data.
- Acceptance: the Definition of Done below is fully checked.

---

## Sequencing & dependencies

```
Phase 0 ─► Phase 1 ─► Phase 2-design ─► Phase 2-impl ─► Phase 3A/3B ─┐
  (quick     (tests)   (blocking         (storage.py    (refactor      │
   wins)                decision)         /cli.py)        SAME files)   ├─► Phase 7
                  └─► Phase 3C/3D (file-disjoint) ──────────────────────┤  (release)
                  └─► Phase 4 (perf; baselines AFTER 3A/3B) ────────────┘
Phase 0 ─► Phase 5 (infra; parallel-OK) ─► Phase 6 (backups) ──────────► Phase 7
```

- Phase 0 first (cheap, de-risks everything); Phase 1 gates 2/3/4.
- **(rev)** Phase 2-design is a blocking gate before 2-impl. **Phase 3A/3B touch
  the same files as Phase 2-impl (`storage.py`, `cli.py`, `api_client.py`) and
  MUST run after it — NOT in parallel** (avoids merge/semantic collisions).
  Phase 3C/3D are file-disjoint and may run in parallel.
- **(rev)** Phase 4 baselines are captured AFTER Phase 3A/3B land (they restructure
  the very functions Phase 4 profiles).
- Phase 5 (infra) parallel-OK after Phase 0 (mostly `deploy/` content). Phase 6
  needs server stable (0–2) + infra (5). Phase 7 closes everything.

Suggested milestones: **M1** = Phase 0+1 (hardened, tested core). **M2** =
Phase 2 (complete E2EE feature model). **M3** = Phase 5+6 (deployable hardened
box with backups). **M4** = Phase 3+4+7 (clean, fast, released).

---

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| App-context refactor (1A) introduces regressions before integration tests exist | Med | High | Land 1B's smoke tests first, refactor incrementally, keep Phase-0 suite green at each step |
| AAD-width fix (0.2 option a) breaks existing stored files | Low | High | Prefer the non-breaking assertion; gate the wire change behind a PROTOCOL_VERSION bump + migration |
| fsync change (4B) weakens durability | Med | Med | `[APPROVAL: durability]`; rely on finalize re-verification; document the power-cut behavior |
| Public-wrapping design (2B) leaks metadata or caches keys | Med | High | Design spike with explicit leakage analysis; keep fail-closed; security re-review the design |
| Dead-code deletion (3C) removes something intended as future API | Low | Med | `[APPROVAL: delete]`; confirm no importers (grep) and no roadmap need before removing |
| Infra hardening (5) locks the operator out (kill-switch/firewall) | Med | High | Console-only recovery path; test scheduled-uptime + kill-switch on a throwaway box first |
| Dependency bumps (0.6) change parser behavior | Med | Med | Re-run full + new fuzz suite against the bumped versions before adopting |
| **(rev)** Phase 2-impl and Phase 3A/3B edit the same files (storage.py, cli.py) | High | High | Serialize: 3A/3B run AFTER 2-impl; only 3C/3D parallel. Encoded in the sequencing diagram |
| **(rev)** 2D metadata-AAD change breaks decrypt of already-stored files | Med | High | Same as 0.2(a): gate behind PROTOCOL_VERSION + domain-tag bump + migration; `[APPROVAL: api]` |
| **(rev)** 4B-b (drop per-chunk fsync) accepts a corrupt blob finalize can't detect | Med | High | finalize must re-hash bytes from disk OR keep per-chunk fsync; document failure mode; `[APPROVAL: durability]` |

---

## Accepted limitations (explicit out-of-scope decisions) **(rev)**

The Definition of Done requires every README §11 gap to be closed OR explicitly
accepted. These two are accepted as out-of-scope unless a future requirement
revisits them — recording them here so the DoD can be honestly checked:

- **File version history (`MetadataBlob.version_number` / `blob_ids`)** — these
  fields exist but are placeholders (`version_number=1`, `blob_ids=[]` always).
  Full versioning is a feature, not a defect; deferred. If implemented later it
  interacts with Task 2D's metadata version-binding.
- **Merkle range-proof downloads** — `merkle_proof`/`verify_merkle_proof` in
  `shared/crypto.py` are unused; the client recomputes the full root instead.
  Decision: treat range proofs as out-of-scope and DELETE the unused functions in
  Task 3C (Phase 4E does NOT wire them). If ever revived, the verifier needs its
  own audit + property tests first (CRY-L1).

## Definition of Done (final product)

- [ ] All review findings (table above) resolved or explicitly accepted with a
      documented rationale.
- [ ] `pytest` + `cargo test` green, including the new integration and
      property/fuzz tiers; CI enforces the full toolchain + audits.
- [ ] README §11 "known gaps" list is empty or each remaining item is a
      consciously accepted limitation with a note.
- [ ] Server reachable only via WireGuard (verified externally); AppArmor +
      systemd sandboxing in enforce mode; separate service users; read-only root.
- [ ] Scheduled uptime + operator kill-switch verified on hardware.
- [ ] Public/shared/private/owner key delivery all work through one fail-closed
      path with no plaintext keys at rest.
- [ ] Encrypted backup→restore drill passes; backup media has no plaintext.
- [ ] Threat model + runbooks written; external audit recommended before
      production data.
