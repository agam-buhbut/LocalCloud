# Sector G — docs

**Owns:** README.txt, CHANGELOG.md, docs/threat-model.md, docs/release-checklist.md, docs/runbooks/operations.md, docs/runbooks/key-rotation.md, docs/benchmarks.md. (NOT docs/superpowers/plans, NOT docs/pentest-2026-06-22.md.) Prose only — verify each claim against the CURRENT code before editing.

- **DOCS-1** — README PART I "what is implemented" states schema v5; actual `SCHEMA_VERSION = 6` (server/database.py:20). Fix to v6. Re-scan the whole "what is implemented" block for other stale counts (test counts: confirm against current suite — note it grew with this remediation pass; state an approximate, not a brittle exact number, or mark "see CI").
- **DOCS-3 / DOCS-6** — README "known gaps" claims `merkle_proof()/verify_merkle_proof()` still exist and the build section references `client/sharing.py`; both were removed. Delete/repair those references (grep the repo to confirm removal first).
- **DOCS-2** — docs/release-checklist.md:45-61 lists "Python lockfile" as the sole open item, but `uv.lock` is committed and CI gates `uv lock --check`. Close that item (mark done / remove); re-scan the checklist for other items the repo already satisfies.
- **DOCS-4 / DOCS-7** — document three user-facing client mechanics currently only in code: the **TOFU owner-pubkey pin store** (where pins live, the "owner identity changed — refusing" fail-closed behavior, and the `--sender-pubkey` override) — add to README client-usage + key-rotation runbook; the **`.session` token** (where it's saved, expiry, that it's peer-bound); and the **keystore auto-lock** timeout (default, the "key store is locked" error, how to re-unlock).
- **DOCS-5** — fix the dangling cross-reference at README:196-197 and add the missing caveat that `unshare` is server-side revocation only (a recipient who already downloaded keeps their copy/keys).
- **DOCS-8** — add a short "Internal review labels" note (README development section or a CONTRIBUTING note) explaining the `#Fxx` / `Round-N` / `item-2x` comment labels refer to internal review/phase cycles with no public tracker — so a reader isn't hunting for one. (Do not touch the code comments.)
- **DOCS-9** — docs/benchmarks.md: add a one-paragraph "Reproduce" note (exact commands / where the numbers came from) OR state plainly the numbers are indicative and the harness is not committed. Coordinate with sector A if a tiny bench script is added (none currently planned).
- **SVC-1 note** — mention in the relevant doc that MemoryDenyWriteExecute was hardware-validated against argon2 (pentest V15) so operators don't disable it out of caution. (The systemd comment itself is sector H.)
- **CHANGELOG.md** — add an entry summarizing this remediation pass (the fixes landing across sectors). Keep the existing style.

## Verify
No tests. After edits, re-grep the repo to confirm no remaining reference to removed symbols (`merkle_proof`, `client/sharing.py`) in README. Spell-consistent with existing docs. No git.
