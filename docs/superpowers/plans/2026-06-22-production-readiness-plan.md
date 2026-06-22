# LocalCloud — Production-Readiness Assessment & Plan

_Date: 2026-06-22 · Branch: `harden/review-plan-execution` @ e91feb3_
_Method: empirical (real test/lint/audit/e2e runs) + 26-agent adversarial audit workflow with per-finding verification + manual spot-check of load-bearing findings._

---

## 1. Exact current state (empirically verified, not claimed)

| Gate | Command actually run | Result |
|------|----------------------|--------|
| Python tests | `pytest -q` | **334 passed / 0 failed** (711s; Argon2id + Hypothesis dominate) |
| Rust tests | `cargo test` | **27 passed / 0 failed** (600s; real Argon2id) |
| Format | `black --check .` / `isort --check` | clean (exit 0) |
| Lint | `ruff check .` | clean (exit 0) |
| Lint (deep) | `pylint client server shared` | **9.84/10**, no errors (convention/warning only) |
| Types | `pyright` | **0 errors / 0 warnings** |
| Rust format | `cargo fmt --check` | clean |
| Rust lint | `cargo clippy --all-targets -- -D warnings` | clean (exit 0) |
| **Rust supply chain** | `cargo audit` | **FAILS (exit 1)** — 2 advisories (see F7) |
| **Live E2E** | server up → login → enroll → upload → self-share → download → share→bob→download | **byte-for-byte round trip OK** |
| Deploy static | `sh -n`/`dash -n` ×8 scripts, `systemd-analyze verify` ×5 units, `apparmor_parser -N/-Q`, `nft` grammar | clean (syntax); hardware checks pending |

**Bottom line:** the cryptographic core and the private/shared/owner key-delivery paths are correct and *empirically proven against a live process*. Static/dynamic gates are green **except `cargo audit`**. The hostile-box deploy tree is internally consistent and statically valid but has **never run on hardware**.

Crypto confirmed real and wired: per-file XChaCha20-Poly1305 streaming AEAD (192-bit per-chunk nonces, ChunkAAD binding), BLAKE2b Merkle tree with domain-separated leaf/node tags (closes CVE-2012-2459), Ed25519-signed root verified *before* any chunk is decrypted, metadata sealed under `build_metadata_aad` (binds file_id‖merkle_root‖version), Argon2id(512 MiB,t=3) identity keystore at rest, ephemeral-static X25519+HKDF+XChaCha20 file-key wrapping for sharing with sender/recipient/ephemeral/file_id binding and low-order-point rejection.

---

## 2. Confirmed findings (deduped, after adversarial verification)

> Severity = corrected severity after verification. Every item quotes real code.

### Security / correctness — fixable in-repo now

- **F1 · HIGH · Download owner-pubkey TOFU pin is claimed but not implemented.**
  `client/cli.py:192-216` (`_resolve_owner_pubkey`). Docstring says "the client treats it as a TOFU-pinnable identity," but the code returns `client.get_owner_pubkey(file_id)` (a *server-supplied* value) with no persistence and no comparison. A hostile server can serve a different Ed25519 pubkey per download and re-sign, so the signature check provides **no protection on non-owner downloads**. The directory self-signature does not help: a server-minted synthetic identity self-signs validly.
  **Fix:** persist first-seen owner pubkey per `(owner_account)` (or file_id) in a `0600` pin file under the key dir; `hmac.compare_digest` on subsequent downloads; fail closed on mismatch. Add tests.

- **F2 · HIGH · Cross-version whole-file rollback/replay is undetectable; the code comment claims otherwise.**
  `client/encryptor.py:10` ("...to detect server rollback") + `:200-207` (`version_number` written `=1`) + `:325-345` (verify path). The Ed25519 signature pins integrity *within one version*; a hostile server can serve a **stale but validly-signed older version** and the client accepts it. `version_number` is dead signed-out state (written, deserialized, never compared).
  **Fix (decision required — see §4):** either (a) correct the comment + document rollback as out-of-scope + mark/remove `version_number`; or (b) sign `version_number`/epoch into `build_merkle_signing_input` + `FileHeader` and keep a client-side high-water pin (shares F1's pin store).

- **F3 · MEDIUM · Single-worker guard is blind to `hypercorn --workers`.**
  `server/auth.py:539-590` (`assert_single_worker`) only reads `WEB_CONCURRENCY`/`HYPERCORN_WORKERS`/`LOCALCLOUD_WORKERS` env vars. The documented scaling knob (`--workers N`) silently bypasses the guard, and multi-process breaks the in-memory session/rate-limit/nonce assumptions.
  **Fix:** enforce single-process at runtime — `flock`/`O_EXCL` pidfile on `db_path` (or abstract unix socket) in `create_app`; refuse to start if the lock is held.

- **F5 · LOW · `cleanup_orphan_staging_dirs` can rmtree a live upload's staging dir.**
  `server/storage.py:1606-1626`. The background scanner can race `upload_init` (dir created before the DB row is visible).
  **Fix:** in `upload_init`, insert the DB row *before* `makedirs`; on failure delete the row. (Or skip dirs newer than `staging_expiry`.) Add a regression test.

- **F6 · LOW · Brute-force lockout is in-memory/per-process; a restart wipes it.**
  `server/auth.py:256-267`. DB rate-limit rows exist but the in-memory counter is authoritative. (Mitigated: restart is physical-console-only, not attacker-triggerable.)
  **Fix:** make the DB-backed composite `(ip_address, username)` count co-authoritative so lockout survives restart.

- **Minor:** `server/config.py validate()` checks session-secret *length* but not entropy; `deploy/backup/localcloud-backup-copy.sh` + `…-restore-copy.sh` swallow `cp` errors (`2>/dev/null || true`) — a partial blob copy yields a meta.db-valid but ciphertext-missing backup. Fix: add entropy check; fail loudly on copy error.

### Supply chain — gate is currently red

- **F7 · HIGH (gate) · `cargo audit` fails on pyo3 0.24.2.**
  RUSTSEC-2026-0176 (OOB read in `nth`/`nth_back` for `PyList`/`PyTuple` iterators) + RUSTSEC-2026-0177 (missing `Sync` bound on `PyCFunction::new_closure`), both dated 2026-06-11, both fixed by **pyo3 ≥ 0.29.0**. This is a **dependency bump** (major version, ABI-relevant) → owner approval required (§4).

### Performance / scaling — accept-or-fund

- **F4 · MEDIUM · Whole DB serialized behind one connection + one `RLock`.**
  `server/database.py:204-262`. A `finalize` write transaction blocks every read. Fine for single-user; a ceiling for many concurrent users.
  **Decision:** accept the ceiling (document in ops runbook) or open a separate read-only WAL connection.

### Threat-model invariant — ratify

- **F8 · HIGH (by design) · Peer identity == `request.remote_addr` is the sole auth anchor.**
  `server/auth.py:434-450, 219-227`. This *is* the documented WireGuard-only model; it collapses if the server ever binds off-tunnel or shares a subnet with untrusted peers.
  **Decision:** ratify as a hard deployment precondition (fail-closed on public bind) and/or add defense-in-depth (bind tokens to the kernel WireGuard peer pubkey for the source IP).

### Test coverage gaps

- `client/api_client.py` (real HTTP layer: `_raise_for_status`/`_check_response`/`_check_binary_response` + every endpoint call) ships **entirely untested** behind `FakeCloudClient`.
- Untested CLI commands: `init/login/ls/rm/quota/unshare`; `_atomic_write_secret` perms/atomicity; `KeyStore` wrong-password/corrupt-store/generate-over-existing/auto-lock lifecycle.
- `rust/keycore/src/lib.rs` PyO3 boundary has **0 inline tests**; `test_encryptor.py` uses `importorskip("keycore")` so a missing native build silently no-ops the real-crypto roundtrip.
- No CI coverage measurement (`pytest-cov` + threshold).

### Documentation drift

- README PART I is materially stale vs CHANGELOG/code: §1 test counts say "86 Python + 22 Rust" (actual **334 + 27**); §11 "known gaps" lists items now **done** (owner self-wrap, pubkey directory, fuzz/property tests) and references the **deleted** `requirements.txt`; §7 backup marked NOT IMPLEMENTED though `deploy/backup/` exists; §5.3/§5.4 understate the now-implemented owner self-share; "deployment … NOT in this repo" though `deploy/` exists.

---

## 3. What's left (grouped) & sequenced plan

**A. Code-now (no owner gate; bounded; I can do these and verify with tests):**
1. F1 download TOFU pin (+ tests)
2. F3 runtime single-process lock (+ test)
3. F5 orphan-staging race fix (+ regression test)
4. F6 DB-authoritative lockout (+ test)
5. Minor: config entropy check; backup-copy fail-loud
6. Test additions: `api_client.py` HTTP layer, untested CLI commands, KeyStore lifecycle, PyO3-boundary inline tests, `pytest-cov` gate in CI
7. F2 (option a) correct the rollback comment + document scope **[depends on §4 decision]**
8. README PART I rewrite (§1/§5/§7/§11) **[do last, so the gap list is accurate]**

**B. Owner-gated (decisions in §4):**
9. F7 pyo3 ≥0.29 upgrade (dependency)
10. F2 (option b) monotonic version anchor (design + wire change)
11. F4 concurrency model (accept vs WAL read connection)
12. F8 peer-identity ratification / hardening
13. Python lockfile (needs pip-tools/uv dev dep)
14. 2B public visibility (key-committing-AEAD design, or accept PUBLIC-without-keys)

**C. Hardware-gated (cannot be closed from the repo — DoD #4/#5/#7):**
15. Real Debian box: external `nmap` shows only 51820/udp; `aa-status` enforcing (after `aa-complain`→`aa-logprof`); `systemd-analyze security` in hardened range; **verify `MemoryDenyWriteExecute=yes` does not break argon2-cffi login** (remove the line if it does — this could brick every login on first deploy); single-worker under concurrent load.
16. Real WireGuard keys; non-allowlisted peer cannot handshake; `/32 AllowedIPs` enforce 1:1 source-IP↔pubkey; consolidate the duplicated `WG_PORT=51820` (×3) and peer-subnet (×2) constants.
17. Scheduled online/offline timers + `localcloud-killswitch.sh` (port toggles on schedule; kill-switch removes rule + severs sessions; console-only recovery works).
18. Full LUKS backup→wipe→restore drill + `strings(1)` plaintext spot-check on real media.

**D. Before real data:**
19. External security audit (per threat-model & release-checklist recommendation).

---

## 4. Owner-decision gates (these change what I do next)

1. **pyo3 upgrade (F7):** approve bumping pyo3 0.24.2 → ≥0.29.0 to clear the 2 RUSTSEC advisories? Major bump; I re-run the full Python + Rust suites + `cargo audit` to confirm the ABI/boundary still holds. _Hold = document as known advisory and you schedule it._
2. **Cross-version rollback (F2):** in scope or out? Out → correct the comment + document + remove dead `version_number` (smallest honest fix). In → sign a monotonic epoch + client high-water pin (real work; reuses F1's pin store).
3. **Concurrency (F4):** single-user box (accept the one-lock ceiling, document it) or fund the WAL read-connection split?
4. **Peer-identity (F8):** ratify `request.remote_addr`-as-identity under strict single-tunnel WireGuard, or require the kernel-peer-pubkey binding?
5. **Python lockfile:** approve adding pip-tools/uv (dev dep) so a lockfile can be committed, or ship without?
6. **Public visibility (2B):** fund the key-committing-AEAD design, or formally accept PUBLIC-delivers-no-keys and reconcile spec §5.3/§5.4?
7. **Hardware + external audit:** provide a throwaway Debian box + LUKS HDD (required for DoD #4/#5/#7); approve commissioning the audit before real data.

---

## 5. Overall verdict

**Not production-ready yet — but close on the application/crypto layer and well-engineered.** The core is correct and live-proven. Blocking the production label: (1) the F1 TOFU gap (download signature is currently bypassable by the hostile server) and the F2 rollback honesty gap; (2) the red `cargo audit` (F7); (3) a deploy posture that is statically clean but never hardware-validated (incl. the MemoryDenyWriteExecute-vs-argon2 risk); (4) test gaps in the real client HTTP layer + no coverage gate. The code-now body of work is focused and bounded; the rest is genuinely hardware- or owner-decision-bound.

**Recommended path:** land code-now security fixes + test additions → resolve the §4 gates (esp. pyo3, F2) → hardware acceptance suite on a throwaway box → external audit before any real data.

---

## 6. Execution status (2026-06-22 session)

Design reviewed by architect + security agents (`docs/superpowers/plans/2026-06-22-fix-design.md`); implemented; re-reviewed by security + reviewer agents post-implementation (both clean, no Critical/High). Owner decisions taken: pyo3 upgrade **approved**; F2 = **document out-of-scope**; F1 = **pin signature path only** (no API change).

**DONE — landed and verified:**
- **F1** download owner-key TOFU pin (sig-path; pin-after-successful-decrypt; corrupt/oversized/symlinked store fails closed; `--sender-pubkey` override warns + replaces). `client/cli.py`. Post-impl security audit: **sound** (the unwrap AEAD self-authenticates the owner key; the metadata-AAD merkle_root binding closes cross-version substitution — two independent fail-closed bindings).
- **F2** rollback honesty (doc/comment only, field kept on wire): `client/encryptor.py:10`, `shared/models.py` `version_number` inert-doc at field + validator, `docs/threat-model.md` Replay row + new out-of-scope entry, README §11.
- **F3** runtime single-process `flock` (defense-in-depth over the env-var check). `server/app.py`.
- **F5** `upload_init` inserts staging row before makedirs (closes the orphan-scanner race). `server/storage.py`.
- **backup** copy scripts fail loud on copy error (was `2>/dev/null || true`). `deploy/backup/*.sh`.
- **F7/pyo3** upgraded 0.24.2 → 0.29.0: builds clean, fmt/clippy clean, **`cargo audit` exit 0** (both RUSTSEC advisories cleared). `rust/keycore/Cargo.{toml,lock}`.
- **Trust-boundary hardening**: `get_owner_pubkey` now length-checks the server-returned key (`client/api_client.py`).
- **Tests added** (31): `test_owner_pin.py` (13), `test_api_client.py` (13), `test_single_worker_lock.py` (3), `test_staging_orphan_race.py` (2).
- **README/threat-model de-staled**: test counts (334/27), removed deleted `sharing.py`/`requirements.txt`, schema v6, §7 backup status, §11 gaps rewritten.

**Verification (empirical):** Python **360 passed / 0 failed**; Rust **27 passed / 0 failed**; black/isort/ruff clean; pylint **9.83**; pyright **0 errors / 0 warnings**; cargo fmt/clippy clean; cargo audit **exit 0**.

**Owner decisions executed (2026-06-22):**
- **2B public visibility = ACCEPT (B):** documented in README §5.3/§5.4 + roadmap; CLI now warns on `--visibility public`.
- **Python lockfile = uv (A):** `uv.lock` committed; CI gained `uv lock --check` drift gate; dev docs updated.
- **Peer-identity (F8) = HYBRID:** the public/unspecified-bind fail-closed guard (already in `config.validate()`) is now pinned by `tests/test_config.py`; the `remote_addr`-as-identity model is ratified in `docs/threat-model.md`. Full WG-pubkey-map binding designed + reviewed, then **deferred** (WG `/32` already stops live IP-takeover; map adds only churn/misconfig detection at the cost of a new root-trust file). See `2026-06-22-f8-peer-binding-design.md`.
- **Concurrency (F4) = ACCEPT (A):** single-conn ceiling documented in `docs/runbooks/operations.md`.
- **Hardware box:** acceptance script built (`deploy/scripts/localcloud-acceptance-check.sh`) for the operator to run on the box (DoD #4/#5/#7, incl. the MemoryDenyWriteExecute-vs-argon2 login probe). Referenced from the ops runbook.
- **External audit:** owner handles it.

**STILL OPEN (cannot close from the repo):**
- Hardware-gated (DoD #4/#5/#7): run `localcloud-acceptance-check.sh` on the box; resolve any FAIL.
- External security audit before real data.
- F6 (durable lockout): **dropped** — already a documented accepted limitation (`auth.py:262-265`).
