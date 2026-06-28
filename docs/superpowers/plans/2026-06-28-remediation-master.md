# LocalCloud Remediation — Master Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development / executing-plans. Each sector below has its own plan file. Steps tracked via the session task list + git commits.

**Goal:** Fix every issue surfaced by the 2026-06-27 full review (verified backlog), in sector passes, each with its own plan + agents + verification, keeping the toolchain green throughout. Real-hardware deploy acceptance is the LAST step, only after all code/docs/test work lands.

**Architecture:** Sector passes drawn along **disjoint file ownership** so passes can run as parallel agents without edit conflicts. After each wave: main loop runs the full toolchain (`black → isort → ruff → pylint → pyright → pytest` + `cargo fmt/clippy/test/audit`), fixes any breakage, commits the wave, then an adversarial verification workflow re-checks the wave's diff. Multiple passes until clean.

**Tech stack:** Python 3 (Quart, PyNaCl, argon2-cffi, cbor2, httpx, click), Rust (PyO3 keycore), SQLite, pytest+hypothesis.

## Global Constraints (verbatim, apply to every task)
- Python: type hints on all signatures; black(88)+isort(black profile); ruff+pylint(≥9.8)+pyright clean; **specific exceptions only**; errors→stderr/data→stdout; pathlib over os.path; `raise X from e`.
- Rust: rustfmt (`imports_granularity=Crate`), clippy pedantic + `-D warnings`, `?` over `.unwrap()` outside tests.
- **Hard stops (still honored even under the autonomous goal):** never modify an existing test to mask a code bug (fix the code); never change a public API/signature silently — if a fix needs one, scope it and note it; **new dependency** (`pytest-cov`, dev-only) is pre-declared HERE as the required flag; no file deletes/renames without noting them.
- Branch `remediation/fix-review-findings`; commit per verified finding/sector; do not push.

## Sectors (disjoint file ownership)

| ID | Sector | Owns (code + its tests) | Findings | Plan file |
|----|--------|-------------------------|----------|-----------|
| A | server-core | server/storage.py, database.py, quota.py, policy.py; test_database/storage*/api_upload/staging_orphan_race | **MIG-1(H)**, MIG-2, STG-1, STG-2, STG-3/4/5, PERF-1/2/3 | 2026-06-28-remediation-server-core.md |
| B | server-auth | server/auth.py, timing.py; test_auth*/api_auth/rate_limit_rows/timing_equalization | AUTH-1, AUTH-2, AUTH-3 | (in security-crypto plan) |
| C | server-app-config | server/app.py, config.py; test_config/startup_invariants | APP-1, APP-2, CFG-1 | (in server-core plan) |
| D | shared-crypto | shared/crypto.py, models.py, io.py, file_ids.py, exceptions.py; test_models/property_* | CRYPTO-1/2/3, IO-1, EXC-1 | (in security-crypto plan) |
| E | rust-keycore | rust/keycore/** | CRYPTO-4/5/6/7 (doc/comment + contract) | (in security-crypto plan) |
| F | client-ux | client/*.py; test_cli/api_client/encryptor/keymgmt + new test_keystore | RM-1, ERR-1/2, STDIO-1, ORDER-1, VAL-1, TLS-1, FILENAME-doc, KS-1/CLI-1/CLIENT-1 tests | 2026-06-28-remediation-client-ux.md |
| G | docs | README.txt, CHANGELOG.md, docs/** (excl. plans) | DOCS-1..9, SVC-1 note | 2026-06-28-remediation-docs.md |
| H | deploy | deploy/** | ACC-1/2/3, NFT-1/2, BKP-1/2/3, SVC-1/2 | 2026-06-28-remediation-deploy.md |
| I | tests-ci | pyproject.toml, .github/workflows/ci.yml | COV-1, SKIP-1, PYRIGHT-1 | (in master, run LAST) |

## Decisions taken (so passes don't stall on them)
- **AUTH-1:** peer-scope the legacy per-username DB rate-limit gate to `(ip_address, username)` so it matches the #H11 composite limiter's blast radius — preserves brute-force protection, removes the cross-peer lockout DoS, honors the code's own documented guarantee. (Not removing the gate; not switching to global lockout.)
- **MIG-1:** move the post-v1 `CREATE INDEX` statements out of `SCHEMA_SQL` into the migration that introduces their column; keep `SCHEMA_SQL` index creation only for columns present at table creation. Add real v1/v2/v3→v6 upgrade tests.
- **GODFILE-1 (cli.py split):** deferred — structural change, LOW severity, behavior-neutral. Revisit only if budget remains after all behavioral fixes.
- **PERF-1 incremental staging counter:** do it in sector A alongside STG accounting (coupled), guarded by a before/after micro-measurement; if it complicates the STG-1/3 fixes, ship the STG correctness fixes first and leave PERF-1 as a measured note.

## Execution waves
1. **Wave 1 (blockers, parallel disjoint):** A, B, C, D — HIGH+MEDIUM correctness/security. Verify + commit + adversarial re-check.
2. **Wave 2 (parallel disjoint):** F, E, G, H. Verify + commit + re-check.
3. **Wave 3:** I (coverage gate) — last, so the coverage number reflects all new tests.
4. **Wave 4 (verification):** full toolchain + whole-diff review workflow → second fix pass for anything found.
5. **Final:** real-hardware deploy acceptance (operator-run) — only once 1–4 are green.

## Verification protocol (every wave)
- Agents edit only their owned files + write/extend tests (TDD: failing test first), run their SCOPED tests, and **do not** run repo-wide formatters or git. Main loop runs the full toolchain + commits.
- A fix is "done" only when: its new test failed before and passes after, the full suite is green, and toolchain is clean.
- After commit, an adversarial workflow re-reads each fix's diff and tries to refute correctness/regression; survivors of refutation → second pass.

## Resumption (usage limits)
Progress is durable via: this plan + sector plans, the session task list, and per-finding git commits on the branch. On reset, resume from the first not-`completed` task; `git log --oneline` shows what landed. The active `/goal` Stop hook is the loop that re-engages work until the condition holds.
