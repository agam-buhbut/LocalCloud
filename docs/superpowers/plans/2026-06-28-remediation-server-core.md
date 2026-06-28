# Sector A — server-core (correctness + perf)

**Owns:** server/storage.py, server/database.py, server/quota.py, server/policy.py + tests test_database.py, test_storage_*.py, test_api_upload.py, test_staging_orphan_race.py. **No public signature changes.** TDD: failing test first.

## MIG-1 (HIGH) — migration crashes on connect for schema < v4
**Root cause:** `_init_schema` (database.py:281-284) runs `executescript(SCHEMA_SQL)` *before* migrations. `SCHEMA_SQL` defines tables with all v6 columns AND `CREATE INDEX` statements; on an existing old table `CREATE TABLE IF NOT EXISTS` skips (no new columns), then `CREATE INDEX … ON login_attempts(ip_address,…)` (line 72) and `… ON staging_uploads(owner_id, finalizing,…)` (line 123) reference columns not yet added → `OperationalError: no such column`.

**Fix (split tables from indexes; apply ALTERs per-statement):**
1. In database.py, strip **all** `CREATE INDEX …` out of `SCHEMA_SQL` so it creates **tables only**.
2. Add `SCHEMA_INDEXES_SQL` = every `CREATE INDEX IF NOT EXISTS …` (idx_login_attempts_user_time, _ip_time, _time, idx_files_owner, idx_files_visibility, idx_file_shares_user, idx_staging_uploads_owner).
3. In `_init_schema`: run `executescript(SCHEMA_SQL)` (tables) → version insert/migration block → **then unconditionally** `executescript(SCHEMA_INDEXES_SQL)` (idempotent, runs for both fresh installs and upgraded DBs once columns exist).
4. Migration constants keep only their `ALTER` statements (index creation now centralised in SCHEMA_INDEXES_SQL); leave the `CREATE INDEX IF NOT EXISTS` in migrations or drop them — both safe, prefer dropping for single-source-of-truth.

**Tests (test_database.py):** build a real **v1-shaped** DB (users w/o session_version/ed25519/x25519/self_sig; login_attempts w/o ip_address; no staging tables or v3-shaped staging w/o finalizing) + `schema_version=1`, insert a user row, then `Database(path).connect()`:
- asserts no exception, final `schema_version == 6`,
- the user row survives with new columns defaulted,
- `ip_address`/`finalizing`/`x25519_pubkey` columns + `idx_login_attempts_ip_time`/`idx_staging_uploads_owner` indexes exist (`PRAGMA index_list`).
Repeat for v2- and v3-shaped DBs. These FAIL before the fix (OperationalError), pass after.

## MIG-2 (MEDIUM) — two-ALTER migrations not idempotent under crash-between
**Fix:** apply each migration's ALTERs **one statement at a time**, each wrapped in the duplicate-column-tolerant try/except (so ALTER#2 still runs when ALTER#1 is a duplicate after a partial crash). Represent V3_TO_V4 and V5_TO_V6 as lists of single `ALTER` statements (or a helper `_apply_idempotent_alters(stmts)`), replacing the single `executescript(MULTI_ALTER)`.
**Test:** simulate partial application — manually `ALTER` in only the first v6 column, set version=5, then `connect()`; assert both x25519 columns exist and version==6 afterward.

## STG-1 (MEDIUM) — quota-fail rollback unlinks a re-uploaded chunk, leaving an orphan DB row
`_persist_staged_chunk` (storage.py:408-444) `os.replace`s the chunk into its final path *before* the quota txn, then on failure unconditionally `os.unlink`s it — destroying a previously-accepted chunk on an idempotent re-upload while its `staging_chunks` row survives → finalize promotes a blob missing a chunk.
**Fix (write-temp-then-promote):** write the incoming chunk to a temp name in the staging dir; run the check-and-insert txn; only `os.replace` temp→`{idx}.bin` on success; on failure `os.unlink` the temp (never the established chunk). Keep fsync semantics on the promoted file.
**Test (test_api_upload.py or test_storage_*):** upload chunk idx0 OK; force a quota-fail re-upload of idx0; assert the original chunk file still exists and finalize still yields a downloadable, complete file (no silent missing chunk).

## STG-3 (LOW) — re-upload double-counts bytes in quota/staging accounting
`_check_and_insert` adds `new_chunk_size` on top of `staging` which already includes the prior row for that index. **Fix:** compute a size *delta* for an existing `(upload_id, chunk_index)` (subtract its current `chunk_size`) before the over-quota comparison. **Test:** re-upload same index twice near quota; assert it is not over-rejected and `used`/staging totals are correct.

## STG-2 (MEDIUM) — transient finalize failure strands finalizing=1 + misleading 410
`_run_finalize_commit` (storage.py:759-779) returns 413/409/500 on commit failure without clearing `finalizing`; retry hits `mark_upload_finalizing`→False→"Upload expired" 410, and bytes stay cap-invisible until expiry+grace.
**Fix:** on the recoverable commit-failure branches (quota/transient — NOT a genuine verify abort), reset `finalizing=0` (add `Database.clear_finalizing(upload_id)` or reuse an UPDATE) so the client can retry, and return a status that doesn't claim expiry (413 keeps its meaning for quota; use 503/500 for transient). Honour `_claim_finalizing`'s docstring contract.
**Test:** monkeypatch the commit to raise once; assert finalizing is cleared and a retry is accepted (not 410).

## STG-4 (LOW) — non-atomic open-upload cap
`count_open_uploads` then `create_staging_upload` in two lock acquisitions (storage.py:343,362) lets concurrent inits exceed `MAX_OPEN_UPLOADS_PER_USER`. **Fix:** count + conditional insert inside one `BEGIN IMMEDIATE` (mirror the chunk check-and-insert). **Test:** drive two concurrent inits at the cap via the Database API; assert the cap holds.

## STG-5 (LOW) — expired-but-uncollected staging excluded from caps
`get_total_staging_bytes` filters `expires_at >= now`, so just-expired on-disk bytes vanish from accounting until GC. **Fix:** either count rows regardless of expiry until reclaimed, or reclaim synchronously on a same-user new upload. Prefer documenting the transient bound + synchronous reclaim on init (cheap). **Test:** create an expired-but-present upload, then a new init by the same user; assert accounting includes/reclaims it.

## PERF-1 (LOW, measured) — O(n²) staging SUM per chunk POST
Self-throttling (downgraded to low). **Fix (only if it doesn't complicate STG-1/3):** maintain a running per-upload byte total on `staging_uploads` (column `staged_bytes`) updated in the same txn as `add_staging_chunk`, and SUM the small per-user set of uploads instead of all chunks. Add a micro-measure (timeit on a 2k-chunk upload) before/after in a comment. If it tangles with STG accounting, ship STG fixes and leave a measured note instead.

## PERF-2 (LOW) — full write+fsync before quota check
Order: quota check first, or write to temp (already done for STG-1) and only fsync on promote. Fold into the STG-1 temp-then-promote change (write temp without fsync, fsync after promote on success) so a rejected over-quota chunk costs no durable write. **Test:** covered by STG-1 test + assert no leftover temp on rejection.

## PERF-3 (LOW) — blocking _safe_path on event loop
Wrap the `_safe_path` calls that guard an FS op in `asyncio.to_thread` alongside that op, or accept + comment. Low priority; do only if clean.

## Verify
Per fix: scoped `pytest tests/test_database.py tests/test_storage_*.py tests/test_api_upload.py -q`. Sector end: full toolchain. Never weaken an existing test.
