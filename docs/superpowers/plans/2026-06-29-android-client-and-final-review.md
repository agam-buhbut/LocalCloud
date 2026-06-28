# Android Client + Final Security Review — Implementation Plan

> **For agentic workers:** Two independent tracks. Track A finishes the security
> review on the main branch; Track B builds the Android client in a SEPARATE git
> worktree. They share no files, so they run in parallel. Steps use `- [ ]`.

**Goal:** (A) Complete the deep pentest + UX + prod-readiness review and ship a
consolidated report; (B) stand up a real Android LocalCloud client in an isolated
worktree, reusing the Rust `keycore` crypto core via UniFFI behind a thin Kotlin app.

**Architecture (Track B):** Per the 2026-06-28 feasibility study, the
security-critical core is ~90% portable. Split the Rust into a pure-logic
`keycore-core` crate (no FFI) with two thin skins — the existing PyO3 `keycore`
(desktop) and a new UniFFI `keycore-mobile` (Android) — so crypto/protocol live
in ONE audited implementation. A thin Kotlin app provides UI, OkHttp transport,
an embedded WireGuard tunnel, WorkManager background transfers, and
biometric/hardware-keystore fast-unlock over the Argon2id keystore root.

**Tech stack:** Rust (keycore: ed25519/x25519-dalek, chacha20poly1305, argon2,
hkdf, blake2, ciborium, zeroize, subtle) + UniFFI; Kotlin/Android (Gradle,
Jetpack Compose, OkHttp, com.wireguard.android, WorkManager, BiometricPrompt);
cargo-ndk for cross-compile. Python/Quart server unchanged.

## Global Constraints

- **Track B is worktree-isolated.** `git worktree add` on a NEW branch
  (`android-client`); never edit the main checkout from Track B. The main
  branch stays `remediation/fix-review-findings`.
- **This environment has Rust but NO Android SDK/NDK.** Therefore: Rust work
  (core split, UniFFI surface, cross-impl vectors) is BUILT + TESTED here with
  cargo; the Kotlin/Gradle app is delivered as **buildable source + `BUILD.md`**,
  not compiled here. Say so explicitly — do not claim the APK builds.
- Toolchain gates (unchanged): Python `.venv/bin/{black,isort,ruff,pylint(≥9.8),
  pyright,pytest}`; Rust `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test`, `cargo audit`. Run from the relevant checkout/worktree.
- No new RUNTIME dependency without flagging. UniFFI/blake2/Kotlin deps are
  Track-B-only and inherent to the Android port (pre-approved by this plan).
- Never weaken an existing test to make it pass; add tests alongside new code.

---

## TRACK A — Finish the security review (main branch, workflow-driven)

Re-runs work that the session limit cut off. Not bite-sized TDD — it is
analysis + synthesis.

### A1: Re-run the 5 cut-off pentest audits + verify
- [ ] Re-invoke the deep-pentest Workflow with `resumeFromRunId` so the cached
      `rust-keycore` + `shared-protocol` audits return instantly and only
      `server-auth`, `server-storage`, `server-core`, `client`,
      `deploy-supplychain` + the Verify phase run.
- [ ] Collect confirmed findings (expect mostly low/info — the surfaces were
      already remediated + live-pentested). Adversarially verify each high/med.

### A2: Re-run the UX install + activation assessment
- [ ] Reviewer agent: trace install (keycore build prereq, pip/uv), the
      activation flow (init → admin create-user → out-of-band pubkey → login →
      enroll → upload), count manual/out-of-band steps + password prompts, the
      ~3.9 s keystore latency felt-impact, error-message quality, doc coverage.

### A3: Apply fixes
- [ ] Cheap doc-reword fixes from the completed audits:
      - `rust/keycore/src/wrapping.rs` module doc: the "sender binding" is an
        anti-grafting domain-separation LABEL, NOT sender authentication;
        content authenticity rests on the Ed25519 Merkle-root signature + TOFU.
      - `shared/models.py` METADATA_CHUNK_INDEX comment: it is only the
        import-time u32-packing tripwire, not part of the metadata AEAD AAD.
- [ ] Any genuinely-exploitable finding from A1: fix with a test + full toolchain.

### A4: Consolidated prod-readiness report
- [ ] `docs/prod-readiness-2026-06-29.md`: executive verdict; then security
      (hardware pentest D1–D6 + P1 + deep pentest results), perf (the measured
      keystore/crypto/query numbers), UX (A2), Android feasibility (the study),
      and an explicit "open gates / not-verified" section. Commit on the main branch.

---

## TRACK B — Android client (separate worktree)

### Task B0: Worktree + Android target shim
**Files:** worktree `../localcloud-android` (branch `android-client`); modify
`rust/keycore/src/secure_memory.rs`.
- [ ] `git worktree add -b android-client <path> HEAD` from the main repo.
- [ ] In the worktree, fix the one concrete portability bug the study found:
      `disable_core_dumps()` gates `prctl(PR_SET_DUMPABLE,0)` on
      `#[cfg(target_os = "linux")]` — Android is `target_os="android"`, so the
      core-dump suppression silently no-ops. Change to
      `#[cfg(any(target_os = "linux", target_os = "android"))]`.
- [ ] Run `cargo test`/`clippy`/`fmt --check` in `rust/keycore` (worktree) — must
      stay green on the host (linux) target; the cfg change is additive.
- [ ] Commit on `android-client`.

### Task B1: Split pure-Rust core + UniFFI mobile skin (cargo-verifiable)
**Files (worktree):** new crate `rust/keycore-core/` (pure logic moved from
`rust/keycore/src/{identity,wrapping,signing,secure_memory}.rs`), keep
`rust/keycore/` as the PyO3 skin depending on it, new crate
`rust/keycore-mobile/` (UniFFI skin). Workspace `Cargo.toml`.

**Interfaces produced (consumed by B2):** UniFFI-exported, Kotlin-visible —
`KeyPair.generate() -> KeyPair`, `kp.sign(msg) -> ByteArray`,
`kp.ed25519PublicKey()/x25519PublicKey() -> ByteArray`,
`kp.wrapFileKeys(fileKey,metaKey,fileId,recipientPub) -> ByteArray`,
`kp.unwrapFileKeys(bundle,fileId,senderPub) -> Pair<ByteArray,ByteArray>`,
`kp.encryptToStore(password) -> ByteArray`,
`KeyPair.decryptFromStore(data,password) -> KeyPair`,
`verifySignature(pub,msg,sig) -> Boolean`. Errors surface as a single opaque
`KeycoreException` (mirror the PyO3 generic-error discipline — no error-class leak).

- [ ] Move the four pure-logic modules into `keycore-core` (no `pyo3` imports);
      `keycore` (PyO3) re-exports them via thin wrappers (behaviour unchanged —
      the existing `cargo test` + the Python `test_keystore.py` still pass).
- [ ] Add `keycore-mobile` with `uniffi` dep + a proc-macro/`.udl` surface
      mirroring the PyO3 methods, calling `keycore-core`. Same length/zeroize/
      generic-error guarantees.
- [ ] Generate Kotlin bindings with `uniffi-bindgen generate` (host build — no
      NDK needed to GENERATE bindings) into the worktree for B2 to consume.
- [ ] **Verify:** `cargo test -p keycore-core` (move the existing crypto unit
      tests + a round-trip wrap/unwrap/keystore vector); `cargo build -p
      keycore-mobile` (host); `cargo clippy -D warnings`, `cargo fmt --check`,
      `cargo audit`. The desktop `keycore` PyO3 build/import must still work
      (rebuild via maturin + `python -c "import keycore"`).
- [ ] Commit on `android-client`.

### Task B2: Kotlin Android app skeleton (source-only; not compiled here)
**Files (worktree):** `android/` — Gradle project (`settings.gradle.kts`,
`app/build.gradle.kts` with cargo-ndk + the UniFFI Kotlin sources), `app/src/main/`
(AndroidManifest, Compose UI, transport, tunnel, work), `android/BUILD.md`.
- [ ] Gradle scaffold: app module, `cargo-ndk` task wiring to build the
      `keycore-mobile` `.so` for `arm64-v8a`/`armeabi-v7a`/`x86_64`, and include
      the generated UniFFI Kotlin bindings.
- [ ] Compose UI flows (thin, calling the Rust core): provision/init keystore,
      login (account password → Bearer token via OkHttp), file list, upload
      (SAF file pick → Rust chunk encrypt → chunked POST with per-chunk server
      hash echo check), download (fetch → Rust fail-closed decrypt → app-private
      output). Mirror the Python client's security decisions (TOFU pin store,
      header/file_id binding, fail-closed) — keep the *decisions* in Kotlin, the
      *crypto* in Rust.
- [ ] Transport + tunnel scaffolding: OkHttp `CloudClient`; `com.wireguard.android`
      GoBackend tunnel brought up around transfers with tuned persistent-keepalive;
      note the single-`VpnService` constraint.
- [ ] WorkManager resumable-upload job stub; BiometricPrompt + Android
      hardware-keystore fast-unlock wrapping the Argon2id root (so routine use
      isn't a ~multi-second Argon2 every action); `allowBackup=false`,
      `FLAG_SECURE` on sensitive screens, app-private decrypted output.
- [ ] `BUILD.md`: exact toolchain (Android SDK/NDK, Rust Android targets,
      cargo-ndk, uniffi-bindgen) + build/run steps. State clearly the app is
      NOT compiled in the dev environment (no SDK/NDK).
- [ ] Commit on `android-client`.

### Task B3 (next increment — describe; implement if capacity allows): protocol-in-Rust
**Files (worktree):** move `shared/crypto.py` chunk AEAD + Merkle + `shared/models.py`
CBOR/AAD into `keycore-core`; expose via both skins.
- [ ] Port chunk encrypt/decrypt, BLAKE2b Merkle (leaf/node tags), ChunkAAD +
      FileHeader/MetadataBlob canonical CBOR into `keycore-core`.
- [ ] **Cross-impl test vectors:** encrypt in Python → decrypt in Rust and
      vice-versa; pin canonical-CBOR + AAD byte strings; assert byte-identical.
      This is the gate that prevents desktop/Android interop or integrity breaks.
- [ ] Differential test: Rust NFKC+casefold username canonicalization vs the
      Python `unicodedata.normalize("NFKC",x).casefold()` over the charset.

---

## Verification of THIS plan

- [ ] Architect-agent review of the plan before execution: validate the
      core-split (does `keycore-core` cleanly separate from PyO3? any dalek/pyo3
      feature coupling?), the UniFFI-alongside-PyO3 decision, the worktree
      isolation, and that B1 keeps the desktop `keycore` green. Flag irreversible
      or risky steps.
- [ ] Self-review (writing-plans): spec coverage (every feasibility-study
      recommendation has a task?), no placeholders, type/interface consistency
      between B1's exported surface and B2's consumers.

## Architect review corrections (applied 2026-06-29)

Verification found real issues; the corrected approach:
1. **B1 SECURITY — no public raw-key accessors.** After moving `IdentityKeyPair`
   into `keycore-core`, do NOT make its `pub(crate)` x25519/ed25519 private-key
   accessors `pub`. Expose `sign` / `wrap_file_keys` / `unwrap_file_keys` as
   `pub` METHODS on `IdentityKeyPair`; refactor the PyO3 skin (`lib.rs:86,155`)
   to call those methods instead of passing raw bytes. Keep raw accessors
   non-public. → security review of the resulting `keycore-core` public API.
2. **B2 depends on B3.** B2's upload/download need the Rust chunk-crypto/Merkle/
   CBOR that only B3 adds. Reorder B3 BEFORE B2 (matches the study's "cross-impl
   vectors green before any UI"), OR scope B2 to provision/login/keystore/list
   with upload/download stubbed pending B3. **This pass: do B0+B1 (verified),
   scope B2 to source-skeleton, B3 next.**
3. **B0 is already done** (worktree + cfg fix exist + committed `1d55e13`); make
   any B0 step idempotent. Real branch is **`main`** (not the non-existent
   `remediation/fix-review-findings`).
4. **B1 byte-format guard (irreversible):** add a PINNED keystore blob + wrap
   bundle vector asserting decrypt/unwrap recover the expected keys, so the
   split can't silently change the on-disk/wire format (would brick existing
   keystores + break desktop↔Android interop).
5. **B1 spec:** crate-types `keycore-core`=rlib, `keycore`=cdylib,
   `keycore-mobile`=cdylib; relocate `Cargo.lock` to `rust/Cargo.lock`; maturin
   verify uses `-m rust/keycore/Cargo.toml`; UniFFI **proc-macro** mode (not UDL).
6. **B1 opaque errors:** `keycore-mobile` maps every `Result<_,String>` to ONE
   fixed-message `KeycoreException` — never surface the inner String (UniFFI's
   default Display would leak cipher/errno internals = error-oracle regression).
   Carry the `decrypt_from_store` local-only timing warning into the UniFFI doc.
7. **Shared keystore format** desktop↔Android is a CONSCIOUS decision: identical
   Argon2id `encrypt_to_store`/`decrypt_from_store`; the multi-second 512 MiB
   Argon2 is a cold-start cost mitigated by TEE/biometric fast-unlock; `m_cost`
   cannot be lowered without breaking interop (the param-band check enforces it).
8. **A3↔B1 merge note:** A3 rewrites `wrapping.rs` doc in place on `main`; B1
   relocates `wrapping.rs` into `keycore-core` in the worktree → eventual merge
   conflict. Carry the same doc reword into the relocated file.

## Execution model

- Track A: re-run the pentest Workflow (resume) + the UX agent on the main branch.
- Track B: create the worktree, then a sequential set of implementer agents (B0→B1→B2)
  operating IN the worktree path. B0/B1 are cargo-verified; B2 is source-only.
- The two tracks are file-disjoint and run concurrently.
