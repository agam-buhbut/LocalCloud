# LocalCloud — Performance Baselines (Phase 4)

> **Discipline:** measure first, optimize second. Every entry below is a
> *measured* baseline, not an intuition. An optimization is only applied when a
> measurement shows a bottleneck at a scale the target deployment will actually
> reach. The target deployment is a **single hardened box, single user (or a
> small trusted set), reachable only over WireGuard** — not a multi-tenant
> service.

## Environment & method

- Captured 2026-06-09 on the dev host (Python 3.13, SQLite via stdlib `sqlite3`,
  WAL, `foreign_keys=ON`, `busy_timeout=5000` — the real `server.database`
  connection init).
- Query plans via `EXPLAIN QUERY PLAN` against the **real schema** built by
  `Database.connect()`, seeded with a synthetic corpus (owned / shared-to-me /
  public files across 51 users). Timings are best-of-5 `perf_counter` of the
  actual `Database` method.
- **Tooling limits in this environment (material to Phase 4):** `py-spy`,
  `line_profiler`, `memory_profiler`, and `strace` are **not installed**
  (`py-spy` would be a new dependency — out of scope without approval), and
  there is **no real deployment, no large corpus, and no concurrent-load
  generator**. Consequently the *concurrency-ceiling* tasks (4A read-connection
  contention, 4F concurrent-login latency/RSS) and the *I/O-split* task (4E
  prefetch) **cannot be honestly profiled here** — their baselines require a
  real soak test on the deployment box. They are listed as BLOCKED-ON-LOAD, not
  silently skipped.

## Measured baselines

### `list_user_files` (Task 4D) — the one query with a scaling cost

```
EXPLAIN QUERY PLAN (unchanged at every corpus size):
  CO-ROUTINE (subquery-3)
    LEFT-MOST SUBQUERY      SEARCH f USING INDEX idx_files_owner (owner_id=?)
    UNION USING TEMP B-TREE SEARCH fs USING INDEX idx_file_shares_user (shared_with_id=?)
                            SEARCH f USING INDEX sqlite_autoindex_files_1 (file_id=?)
    UNION USING TEMP B-TREE SEARCH f USING INDEX idx_files_visibility (visibility=?)
  SCAN (subquery-3)
  USE TEMP B-TREE FOR ORDER BY
```

| corpus (owned / shared / public) | before (best-of-5) | after 4D (best-of-5) |
|---|---|---|
| 50 / 50 / 100  (200 total)   | 0.857 ms | 0.987 ms (≈flat) |
| 500 / 500 / 4000 (5000 total) | **17.613 ms** | **3.419 ms (5.1× faster)** |

**After the 4D rewrite** (committed): each branch is capped with
`ORDER BY created_at DESC LIMIT (offset+limit)` inside a subquery, `UNION ALL`
preserves rows, `GROUP BY file_id` dedups, and the outer sort runs over ≤ 3·cap
rows. The plan now shows the **public branch served directly by
`idx_files_visibility` with no temp b-tree** (it stops at the LIMIT instead of
materializing the corpus); only the small per-user owned/shared branches temp-
sort, plus a bounded outer GROUP BY/ORDER over ≤150 rows. Latency at 5 000
files drops 5.1× and, more importantly, **no longer grows with public-file
count**. At tiny corpora the extra subqueries add ~0.1 ms — noise. Correctness
(dedup across owner∩public / shared∩public, ordering, pagination) is pinned by
`tests/test_list_user_files.py`.

- The per-branch indexes the original plan wanted to *add* already exist
  (`idx_files_owner`, `idx_file_shares_user`,
  `idx_files_visibility(visibility, created_at DESC)`); every branch is an
  index SEARCH, not a scan.
- The cost is the **three TEMP B-trees**: two for the `UNION` dedup and one for
  the final `ORDER BY`. They are built over the *entire* matching set (notably
  the whole public corpus) before `LIMIT 50` is applied, so latency tracks
  total public-file count, not page size — 0.86 ms → 17.6 ms as public files go
  100 → 4000.
- **Relevance to the target deployment:** the public branch scans *all public
  files in the system*. A single-user personal cloud is unlikely to publish
  thousands of public files; at realistic sizes (≤ a few hundred) this is
  ~1 ms. The win is real but only materializes at a corpus the target won't
  reach.

### `get_total_staging_bytes` (Task 4C)

```
EXPLAIN QUERY PLAN:
  SEARCH u USING INDEX idx_staging_uploads_owner (owner_id=? AND finalizing=? AND expires_at>?)
  SEARCH c USING INDEX sqlite_autoindex_staging_chunks_1 (upload_id=?)
```

- The plan assumed a "per-chunk O(n) SUM-with-JOIN" worth replacing with a
  running counter column. **The measurement contradicts that:** the JOIN is
  fully index-driven and `n` is only the *open* staging chunks for *one* user
  mid-upload (a handful). Sub-millisecond. A schema migration to add a counter
  column is **not justified** by the evidence.

### `cleanup_expired_staging` (Task 4D)

```
EXPLAIN QUERY PLAN:
  SCAN staging_uploads
```

- Confirmed full SCAN — the `OR` predicate defeats any index, exactly as the
  plan predicted. **But** `staging_uploads` holds only in-flight uploads (rows
  are deleted on finalize/expiry); at single-user scale it is ~empty. Scanning
  an empty/tiny table is free. Restructuring the predicate is **not justified**
  at the target scale (the plan itself said "measure before bothering").

## Per-task verdict

| Task | Verdict | Basis |
|---|---|---|
| 4A — separate read connections | **BLOCKED-ON-LOAD** | benefit only under concurrent readers; needs `py-spy` + concurrent-download load (absent here). Also an architecture change to the core DB layer with FK/snapshot-consistency prerequisites → needs architect review + a real load test. |
| 4B-a — `synchronous=NORMAL` | **DONE (owner-approved)** | crash-safe under WAL (db cannot corrupt; only the last txn is at risk on power loss). Set in `Database.connect()`; per-chunk file-byte fsync left intact, so file durability is unchanged — only the per-commit metadata-WAL fsync is relaxed. Pinned by `tests/test_db_durability.py`. |
| 4B-b — drop per-chunk `os.fsync` | **NOT DONE (durability kept)** | owner chose to keep per-chunk fsync. `_write_file_bytes` (storage.py:1526) fsyncs each chunk; finalize compares *recorded* hashes, not re-read bytes, so dropping fsync could silently commit a crash-truncated blob unless finalize re-hashes from disk. Left as-is. |
| 4C — quota counter column | **NOT JUSTIFIED** | SUM-with-JOIN is index-driven and tiny (measured). Schema migration unwarranted. |
| 4D — `list_user_files` rewrite | **DONE** | only query with a scaling cost (3 temp b-trees → 17.6 ms @5k public). Rewritten to per-branch `ORDER BY created_at DESC LIMIT (offset+limit)` + `UNION ALL` + `GROUP BY file_id` dedup; public branch now index-served (no temp b-tree). **17.6 → 3.4 ms @5k (5.1×), no longer scales with public count.** Behavior pinned by `tests/test_list_user_files.py`. |
| 4D — `cleanup_expired_staging` | **NOT JUSTIFIED** | SCAN confirmed, but table is ~empty at single-user scale. |
| 4E — download prefetch | **BLOCKED-ON-LOAD** | the plan requires measuring the sequential CPU-vs-network split first; meaningless on loopback with no real network. |
| 4F — configurable Argon2 concurrency | **DONE (knob); justification BLOCKED-ON-LOAD** | `_MAX_CONCURRENT_ARGON2` is now `ServerConfig.argon2_max_concurrent` (env `LOCALCLOUD_ARGON2_MAX_CONCURRENT`, validated ≥1, default 4), threaded through `init_auth`. The *tuning* (p50/p95 login latency + peak RSS under concurrent logins) still needs a real load test; the plumbing is in place to set it without a code change. Tests: `tests/test_config.py`, `tests/test_auth_argon2_limit.py`. |
| 4G — SQLite operational tuning (`wal_autocheckpoint`, `auto_vacuum`, `cache_size`) | **DEFERRED TO DEPLOYMENT** | requires a 24/7 soak test on the box to size; belongs with Phase 5 provisioning. |

## Bottom line

Measure-first produced a mostly-negative result **for the target single-user
deployment**: every query Phase 4 names is ≤ ~1 ms at realistic sizes.

**Applied (owner-approved):**
- **4D** — `list_user_files` rewrite: 17.6 → 3.4 ms @5k public files (5.1×) and
  no longer scales with public-file count. The one evidence-backed query win.
- **4B-a** — `synchronous=NORMAL` under WAL: crash-safe; relaxes the per-commit
  metadata-WAL fsync. File-byte durability (per-chunk fsync) unchanged.
- **4F** — Argon2 concurrency is now configurable (`argon2_max_concurrent`);
  tuning still needs a load test, but the knob no longer requires a code change.

**Not done, by evidence or decision:** 4C and `cleanup_expired_staging` are
unjustified at single-user scale (measured index-driven / empty-table). 4A
(read-connection pool), 4E (prefetch), and the 4F *tuning* are real engineering
but cannot be justified or validated here without a multi-user/large-corpus
deployment plus `py-spy`/`strace`; 4G is deployment-time. 4B-b (drop per-chunk
fsync) was declined to keep file-byte durability. The deferred items remain
open for a future soak test on the real box.

## Client-side & crypto-core (measured 2026-06-28)

Captured on a 4-core dev host (Python 3.13, release `keycore`), `time.perf_counter`
median over N, after a warm-up. Indicative — Argon2id cost scales with CPU.

| Op | Median | Notes |
|---|---|---|
| **keystore lock** (`keycore` Argon2id encrypt-to-store) | **~3.66 s** | one-time on `init` |
| **keystore unlock** (Argon2id decrypt-from-store) | **~3.86 s** | **paid on every key-using CLI command** (enroll/upload/download; `login` does NOT unlock the keystore — it pays only the server-side ~0.7 s argon2) |
| `KeyPair.generate` (Ed25519+X25519) | 0.15 ms | negligible |
| `sign` (256 B) | 0.13 ms | negligible |
| `verify_signature` | 0.23 ms | negligible |
| `wrap_file_keys` (X25519 ephemeral-static) | 0.27 ms | per recipient/file |
| `unwrap_file_keys` | 0.25 ms | per file |
| `encrypt_chunk` (4 MiB XChaCha20-Poly1305) | 20.5 ms | **≈205 MB/s** |
| `decrypt_chunk` (4 MiB) | 14.8 ms | **≈283 MB/s** |
| server `hash_password` (Argon2id) | ~707 ms | login/create-user |
| server `verify_password` (Argon2id) | ~711 ms | login path |

**Read of the numbers:**
- The **Argon2id keystore unlock (~3.9 s) dominates client latency** and is paid
  per command — the single biggest felt-UX cost. For small files it is the whole
  wait; identity/wrap ops are sub-ms and irrelevant. Lowering it trades brute-force
  resistance of the at-rest keystore — an explicit owner knob, not a free win.
- **Bulk content crypto ≈200–280 MB/s** (PyNaCl XChaCha20-Poly1305). A 1 GiB
  transfer is ~5 s of client-side encrypt, so large transfers are crypto/I/O-bound,
  not keystore-bound. A Rust chunk path could lift this but is unjustified at
  single-user scale (YAGNI).
- **Server login Argon2id ≈0.7 s here** (≈0.25 s on the deploy box) — both far
  above the old flat 150 ms timing budget, which is exactly the P1 finding
  (`docs/pentest-2026-06-28.md`): the fix now calibrates `TIMING_BUDGET_S` to
  `max(150 ms, measured×1.30)` at startup so login's equalization deadline tracks
  the real verify cost on the deployment hardware.

## Reproduce

These figures are **indicative single-host measurements, not a committed
benchmark suite** — the ad-hoc timing / `EXPLAIN QUERY PLAN` harness used to
produce them is **not in the repository**, so exact numbers will vary by
machine, Python/SQLite build, and seeded corpus. To reproduce the method
described under "Environment & method": build the real schema with
`server.database.Database.connect()` against a throwaway DB; seed a synthetic
corpus (owned / shared-to-me / public rows across ~50 users); capture query
plans with `EXPLAIN QUERY PLAN` on the actual `Database` methods; and time each
method best-of-5 with `time.perf_counter`. The tasks marked **BLOCKED-ON-LOAD**
(4A read-connection contention, 4E prefetch, 4F login latency/RSS tuning) need a
real soak test on the deployment box — plus `py-spy`/`strace`, absent here — and
cannot be reproduced from this repo.
