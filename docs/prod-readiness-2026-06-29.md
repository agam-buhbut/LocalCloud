# LocalCloud — Production-Readiness Report (2026-06-29)

Consolidates the 2026-06-28/29 push: a real-hardware deploy + pentest, a deep
white-box adversarial pentest of every subsystem, a perf pass, a UX/onboarding
assessment, and an Android-client feasibility study + first implementation
increment. Supersedes nothing; cross-references `docs/pentest-2026-06-28.md`,
`docs/benchmarks.md`, `docs/threat-model.md`.

## Executive verdict

**Ready for its stated purpose — a single-operator, WireGuard-only, E2EE
"hostile-box" personal cloud — once the operator runs the physical deploy
acceptance.** The cryptographic core and protocol are, on independent
adversarial re-audit, **solid**: wrap confusion/forgery, low-order points, nonce
reuse, Ed25519 malleability, Merkle second-preimage, CBOR bombs, and chunk
reorder/truncate/swap are all defended; the hostile-server threat model holds for
**owned** files end-to-end (verified live on hardware). Two genuine issues were
found and fixed this push — a **HIGH** confidentiality gap in the *share to a
directory recipient* path and a **MEDIUM** quota-bypass DoS in finalize — and the
real systemd unit had two "won't even start" deploy bugs (also fixed + verified
on hardware). Not for multi-tenant/shared infrastructure; not audited externally;
the physical LUKS/console/2nd-host acceptance remains the operator's gate.

## 1. Security

### 1a. Real-hardware deploy + pentest (`docs/pentest-2026-06-28.md`)
First deploy via the **actual** systemd unit / LoadCredential / WireGuard /
AppArmor on a Debian 13 box. Surfaced + fixed (all verified on hardware,
acceptance then PASS=14/FAIL=0):
- **D1 (HIGH):** `SystemCallFilter ~@privileged` strips `setfsuid` → hypercorn
  worker SIGSYS-dies, daemon never binds. Fix: `SystemCallErrorNumber=EPERM`.
- **D2 (HIGH):** app rejected systemd's 0440 `LoadCredential` secret → service
  refused to start. Fix: accept group-read when group-owned by the service.
- **D3 (MED):** AppArmor profile attached by a venv `python3` symlink → daemon
  ran **unconfined**. Fix: `AppArmorProfile=` by name + completed the profile
  (`/dev/shm`, `/dev/null`, `attach_disconnected`); now confined, 0 denials.
- **D4/D5 (LOW):** acceptance-script false-positives (entropy vs `strings`; scope
  the 0.0.0.0 check to the service). **D6 (INFO):** `Wants=nftables.service`
  makes the box WG-only on start (lockout footgun) — documented.
- **Verified PASS on hardware:** WG peer-identity spoof prevented (the
  load-bearing claim), bind-confinement (LAN-invisible), IDOR → uniform 404,
  E2EE round-trip byte-identical, at-rest = only documented metadata, argon2
  under the sandbox.

### 1b. Login timing (P1, fixed `7b5dc92`)
The login equalization budget was a flat 150 ms while Argon2id verify is
~250 ms (box) / ~700 ms (dev) — so rate-limited/early-reject 401s returned
sooner, leaking rate-limit state by latency (contradicting #H12). Fixed:
`calibrate_budget()` raises `TIMING_BUDGET_S` to the measured Argon2id cost at
startup; login routes **every** return through the deadline.

### 1c. Deep white-box pentest (7 surfaces, 19 findings, 2 confirmed serious)
Independent adversarial auditors per subsystem, each finding adversarially
verified. **rust-keycore** and **shared-protocol** came back fully solid (only
info-level doc-clarity items). Two confirmed serious, both **fixed this push**:

- **HIGH — directory-share trusts a server-controlled recipient identity**
  (`client/keymgmt.py` resolve_recipient + `client/cli.py` share). On
  `share <file_id> <user>` without `--recipient-pubkey`, the recipient's
  {ed25519,x25519,self_sig} comes entirely from the (hostile) server; the only
  check is internal self-sig consistency — **no anchor**. A hostile server
  substitutes its own keys as "bob", the owner wraps the file keys to them, and
  the server reads the "shared" file. The in-code comments falsely claimed a
  recipient pin that did not exist. **Fix:** a per-recipient-username TOFU pin
  (mirroring the owner-download pin) — first successful directory share pins the
  recipient ed25519; a later server substitution is refused fail-closed;
  `--recipient-pubkey` remains the out-of-band first-contact anchor. Claims +
  threat-model corrected to the honest TOFU model.
- **MEDIUM — finalize strands `finalizing=1` on client disconnect** (quota
  bypass, `server/storage.py upload_finalize`). `CancelledError` (BaseException)
  bypassed the `except Exception` release, leaving a cap-invisible staging row
  that leaks disk past the quota (2nd-user DoS). **Fix:** wrap the post-claim
  section in `try/finally` that releases the claim (shielded) on any
  non-terminal exit. Regression test added.

Other deep-pentest findings were **info/low or defended** (e.g. wrap
"sender-binding-is-a-label" — defended by the Merkle signature + TOFU;
keystore-no-AAD; `transaction()` rollback masking; unbounded HTTP response body
on the client; backup cross-consistency staleness; `uv.lock` not used to
install). The doc-clarity ones were fixed (`abc2920`); the remaining low items
are recommendations below.

## 2. Performance (`docs/benchmarks.md`, measured 2026-06-28)
- **Argon2id keystore unlock ~3.9 s** — the dominant client latency, paid on
  every key-using CLI command; the single biggest felt-UX cost (mitigated only
  by lowering at-rest brute-force resistance — an owner knob, not free). UX fix:
  the CLI now prints an "Unlocking…" line so it no longer looks hung.
- Identity/wrap/sign/verify sub-millisecond (irrelevant).
- Bulk XChaCha20 ~205 MB/s encrypt / 283 MB/s decrypt — large transfers are
  crypto/I-O-bound, not keystore-bound. A Rust chunk path could lift this but is
  unjustified at single-user scale (YAGNI).
- Server login Argon2id ~0.7 s (dev) / ~0.25 s (box); SQLite queries ~1 ms
  (`list_user_files` scales only with public-file count). Concurrent-load
  (4A/4F) remains BLOCKED-ON-LOAD — needs a multi-peer soak the single-user
  target won't reach.

## 3. UX / onboarding
**Moderate-to-rough but fixable for a technical solo operator.** ~15 steps from
a bare machine to first upload; 6 commands; 2 passwords; 1 out-of-band step.
Fixed this push: the **Critical** download trap (downloading your OWN file
required `register-pubkey` but the error misdirected to `--sender-pubkey`) — the
error now names self-registration and README §6 flags the prerequisite; the
~4 s unlock now shows progress. **Remaining recommendations:** publish prebuilt
`keycore` wheels (every client otherwise needs a Rust compiler); add a
one-command quickstart; standardize the two password labels; tune the
insecure-HTTP warning (fires on every command against the WG default).

## 4. Android client (feasibility + first increment)
**Feasible.** The Rust `keycore` is ~90% portable; recommended architecture is a
pure-logic `keycore-core` crate behind two thin skins — the existing PyO3
(desktop) and a new UniFFI (Android) — with a thin Kotlin app (OkHttp,
`wireguard-android` tunnel, WorkManager, biometric/TEE fast-unlock over the
Argon2id root). "Peer identity = WG source IP" survives mobile roaming. Top
risks: Argon2id-on-mobile latency/OOM (512 MiB) and WG tunnel lifecycle.
**Started (branch `android-client`, isolated worktree):** B0 — the Android cfg
shim so `disable_core_dumps` works on Android (committed `1d55e13`); B1 — the
core-split + UniFFI surface, with the architect-mandated corrections (no public
raw-key accessors, opaque mobile errors, pinned byte-format vectors). The Kotlin
app + protocol-into-Rust are the next increments; the Android app is NOT
compiled in this environment (no SDK/NDK) — delivered as buildable source.

## 5. Open gates / NOT verified (operator-owned)
- Physical deploy acceptance: LUKS2 console-only unlock + reboot survival,
  external `nmap` from a 2nd host, live kill-switch, the offline backup-HDD drill.
- External security audit (recommended before storing real data).
- The remaining low-severity deep-pentest items + UX recommendations above.
- Android: real-device Argon2 latency/OOM, on-device build, the Kotlin app.

## Verdict table
| Dimension | State |
|---|---|
| Crypto core / protocol | **Solid** (independent adversarial re-audit) |
| Hostile-server confidentiality | Holds for owned files; **share path fixed** (was HIGH) |
| Deploy (real unit) | **Fixed + hardware-verified** (was 2× won't-start) |
| Perf | Adequate for single-user; keystore unlock is the felt cost |
| UX onboarding | Rough but the critical trap is fixed; wheel + quickstart recommended |
| Android | Feasible; core-split underway |
| Physical/LUKS/2nd-host acceptance | **Operator gate — not done** |
