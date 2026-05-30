---
title: Phase 2 E2EE Protocol Design — owner self-share, public-key delivery, pubkey directory, metadata-version binding
date: 2026-05-30
status: proposed
phase: 2 (design)
author: architect
supersedes: none
implements: README PART I §11 (application-level gaps); PART II §5.3, §5.4, §4
work_items: [2A ARCH-M8/SEC-GAP, 2B SEC-GAP, 2C FEAT-1, 2D CRY-I2]
breaking: schema v5→v6, PROTOCOL_VERSION 1→2, removal of <file_id>.keys.json cache, new HTTP endpoints
---

# Phase 2 E2EE Protocol Design

This is a DESIGN document. It defines wire formats, schema, APIs, message flows, and a sequenced
TDD task list for the Phase-2 implementer. It writes **no production code** and modifies no source
file. Every decision is grounded in the code as it exists today (citations are `file:line`).

## ⚖️ Execution decisions & review revisions (2026-05-30, owner-approved)

This section OVERRIDES the body below where they conflict. It folds the owner's scope
decisions and the two adversarial reviews (crypto/security + implementability — both
verdict *sound-with-changes*).

**Scope this round: implement 2A + 2C + 2D. DEFER 2B.**
- **2B (public visibility) is DEFERRED** pending a *key-committing AEAD* single-bundle design
  that is separately security-reviewed. The owner rejected both weak forms (the
  "documented-limitation / not-confidential-against-the-server" model and the
  "pinned-allow-list" model). Therefore: **do NOT implement** `PUT /visibility`, the
  publish/fan-out flow, `share_bulk`, `MAX_PUBLISH_FANOUT`, or any "public" semantics in this
  round. Record 2B in the master plan's Accepted-Limitations as "deferred — needs committing-AEAD
  design". (A committing AEAD can be built from audited primitives — e.g. a BLAKE2b key
  commitment composed with XChaCha20-Poly1305 — so a future design need not introduce a custom
  primitive; that design is a separate deliverable.)

**2D: HARD CUTOVER (no v1 compatibility-read).**
- `PROTOCOL_VERSION` 1→2; `FileHeader.validate()` accepts **only** version 2 (NOT a
  `SUPPORTED_VERSIONS` set). There is **no §6.6(A) v1 compatibility branch** — this deletes the
  version-downgrade oracle the security review flagged. Existing v1 files (if any) must be
  re-uploaded; there is no production data yet. Audit `tests/test_models.py` for any
  `version == 1`/`== PROTOCOL_VERSION` assertions and update them to v2 (a legitimate test update,
  not a weakening).
- Corrected **2D negative test** (the doc's T-2D.6 as written trips the signature gate, not the
  metadata AAD): build TWO genuine, correctly-signed v2 files of the same `file_id` (versions M
  and N), then feed file-M's header+chunks with file-N's `encrypted_metadata` and assert a
  `DecryptionError` from the **metadata AEAD** specifically. Keep T-2D.4 (root computed before
  metadata; metadata never a Merkle leaf) as a hard gate.

**Cross-cutting fixes to fold in (from the reviews — apply without further approval):**
- **Blueprint wiring:** the `/api/users/*` endpoints (enroll, directory) have no home today
  (`app.py` registers only `auth_bp` + `storage_bp`). Create `server/users.py` with
  `users_bp = Blueprint("users", __name__, url_prefix="/api/users")` and register it in
  `create_app` — and keep `assert_no_forwarded_header_middleware(app)` running LAST.
- **New key-glue lives in a NEW module `client/keymgmt.py`** (NOT a revived `client/sharing.py`).
  Phase 3C still deletes the dead `client/sharing.py` as planned — no cross-phase conflict.
- **Directory lookup hardening is MANDATORY, not conditional:** `GET /api/users/<u>/pubkeys`
  must use a constant-deadline envelope mirroring `_SHARE_TIMING_BUDGET_S` AND a fixed-size
  response (pad present-vs-absent to identical length) so neither timing nor body length is an
  enumeration oracle. Add equality assertions for both.
- **`enroll_x25519`:** collapse the `409 "No identity key"` into the generic `400` (the client
  knows its own Ed25519 state locally) to preserve uniform-response discipline.
- **`self_keys` / any stored ephemeral-static bundle:** validate length is **exactly 136 bytes**
  (PUBKEY 32 + NONCE 24 + PAYLOAD 64 + TAG 16), not the loose 136..4096 range.
- **Self-wrap depends ONLY on the local keystore X25519** (`KeyStore.x25519_public_key()`), NOT on
  directory enrollment. Add an acceptance test: an owner whose Ed25519 is registered but whose
  X25519 is NOT yet enrolled can still self-decrypt. Note in the design that AAD binds
  `recipient_pubkey`, so an X25519 rotation would orphan existing self-share/recipient bundles —
  record as a future key-rotation item (Phase 7), out of scope here.
- **`canonicalize_username` must be byte-identical on client and server** over the same input the
  enroll signature covers. Put the single implementation in **`shared/`** (the client must not
  import from `server.*`). This converges with Phase 3B's dedup — place it in `shared/` now.
- **`migrate-keys`:** validate each cached `file_id` before building the `/self_keys` URL;
  require/inject a session; downgrade "shred-and-unlink" to a plain best-effort `unlink` with a
  comment that in-place overwrite is NOT a secure wipe on CoW/SSD/journaled FS and that a
  `keys.json` which ever existed should be treated as potentially compromised; assert a failed
  POST leaves the JSON intact (fail-closed).
- **`enroll_x25519` self-signature** must bind the **canonical** username; add a test that a
  self-sig over a non-canonical username is rejected, plus the client/server canonicalization
  parity test.

Everything below stands EXCEPT the 2B/public sections and the §6.6(A) compatibility path, which
are out of scope this round per the decisions above.

## Master-plan invariants (held throughout)

These are non-negotiable and gate every decision below. (README PART II §5, §10.)

1. The server is a **hostile storage box**: it never sees plaintext, `file_key`, `meta_key`, or any
   unwrapped symmetric key. It stores only ciphertext, encrypted metadata, server-visible plaintext
   (filename, visibility, coarse padded size), and **opaque wrapped-key bundles**.
2. **Fail-closed**: any verification or acquisition failure aborts the operation; no partial /
   unverified plaintext is exposed (`client/encryptor.py:457-467`).
3. **No custom primitives**: reuse `shared/crypto.py` (XChaCha20-Poly1305, BLAKE2b, HKDF) and the
   audited `rust/keycore/src/wrapping.rs` ephemeral-static ECDH path unchanged.
4. **Generic error paths**: no enumeration oracle; uniform responses (`server/storage.py:746`,
   `server/auth.py:607-612`).
5. **Forward secrecy**: per-file random keys; per-recipient ephemeral-static wrap; no shared global
   keys; no server-side caching of wrapped keys beyond stored share rows.

---

## 1. Overview

Phase 1 delivers per-file encryption, signed Merkle roots, ephemeral-static key wrapping, and a
server that enforces visibility policy without reading plaintext. Four gaps remain (README §11):

- **2A** Owner self-access uses a **plaintext on-disk cache** `<file_id>.keys.json`
  (`client/cli.py:266-284`), which violates "keys encrypted at rest" the moment the file is read,
  and forks the key-acquisition path (owner = local cache; everyone else = server wrapped bundle,
  `client/cli.py:347-378`).
- **2B** "Public" visibility authorizes ciphertext access for any authenticated user
  (`server/policy.py:37-38`) but there is **no key delivery**: a non-owner can read ciphertext but
  cannot obtain `file_key`/`meta_key` unless an explicit share row exists (README §11 first bullet).
- **2C** Recipient X25519 key discovery is **out-of-band** (`client/cli.py:476-480`,
  `README §6`). The server stores only Ed25519 (`server/database.py:50`); there is no directory
  and no cryptographic link between a user's Ed25519 identity and the X25519 key used for wrapping.
- **2D** The encrypted metadata blob is bound to the file by `file_id` and the metadata sentinel
  AAD only (`client/encryptor.py:211-216`), **not to the specific file version** (Merkle root). A
  hostile server can pair version-N's metadata blob with version-M's chunks+header as long as the
  `file_id` matches and both pass their own AEAD checks.

This document resolves all four into one coherent change. The unifying idea for 2A/2B is: **the
file's keys are always delivered as a wrapped bundle from the server**, for the owner (self-share)
and for every authorized recipient (per-recipient wrap), reusing exactly one audited code path
(`wrapping.rs`). 2C provides the authenticated X25519 directory that makes 2A/2B's wraps possible
without out-of-band key exchange. 2D closes the metadata/version-substitution gap with a one-field
AAD extension and a `PROTOCOL_VERSION` bump.

### What changes, at a glance

| Item | Layer | Kind | Approval needed |
|------|-------|------|-----------------|
| 2A self-share bundle on upload | client + server (reuses share row) | behavior + flow | keys.json removal (breaking) |
| 2B public delivery = per-recipient fanout wrap | client (publish/enroll) | behavior | new endpoints (API addition) |
| 2C X25519 + self-sig enrollment & directory | server schema + client + admin | schema v6 + API | schema v6, new endpoints (breaking) |
| 2D metadata AAD binds merkle_root | shared wire format | wire change | PROTOCOL_VERSION bump (breaking) |

---

## 2. Threat-model delta

Phase 1's model (README §10) is unchanged in its assumptions. Phase 2 **closes** these residual
gaps and introduces these **new** considerations.

### Closed by Phase 2

- **T-2A (key-at-rest leak via cache):** the plaintext `keys.json` exposes `file_key`+`meta_key`
  for every uploaded file to anyone who reads the client's home dir (backup, second user, stolen
  laptop without FDE). After 2A the owner's keys exist on disk only inside the password-encrypted
  keystore and as a server-side bundle wrapped to the owner's X25519 key — same protection as a
  recipient's bundle.
- **T-2B (public files undecryptable / ad-hoc sharing):** public files become decryptable by the
  intended audience through a wrapped bundle, not a plaintext side channel.
- **T-2C (X25519 substitution by the server):** today a sharer must obtain the recipient's X25519
  key out-of-band. If a directory simply returned an X25519 key, the hostile server could substitute
  its own key and harvest `file_key`/`meta_key` for any "shared" or "published" file. 2C binds
  X25519 to Ed25519 with a **self-signature**; a sharer who has pinned the recipient's Ed25519
  fingerprint out-of-band transitively authenticates the X25519 key, so the server cannot substitute.
- **T-2D (metadata/version mismatch):** binding `merkle_root` into the metadata AAD makes a metadata
  blob decrypt **only** against the file version whose chunks produce that root.

### New considerations introduced by Phase 2

- **T-N1 (publish-time fanout leakage):** 2B wraps the file keys to *every enrolled user* at publish
  time. This **reveals to the server the set of enrolled recipients of a public file at publish
  time** (one share row per enrollee) and creates a **wrap-fanout cost** O(enrolled users). Bounded
  and analyzed in §4 and §7.
- **T-N2 (directory membership / enrollment oracle):** the directory lookup must not reveal whether
  a username exists or merely lacks a key. Handled by a **uniform response** (§5C).
- **T-N3 (self-signature confusion / cross-protocol):** the Ed25519 self-signature over the X25519
  key must be domain-separated so it cannot be replayed as a file-Merkle signature or a future
  signature type. Handled by a dedicated context tag (§5C).
- **T-N4 (stale public membership):** a user who enrolls *after* a file was published has no share
  row for it. Defined behavior in §4 ("re-publish to admit"), explicitly not an automatic grant.
- **T-N5 (self-share is not extra exposure):** the owner already holds `file_key`/`meta_key`;
  wrapping them to the owner's own X25519 key and storing the bundle adds no plaintext exposure and
  the bundle is opaque to the server (same AEAD as any share). Forward secrecy is preserved because
  the wrap is ephemeral-static (`wrapping.rs:97-101`).

### Explicit non-goals (unchanged from Phase 1)

Traffic analysis from filenames/padded sizes, client-side compromise, live coercion, total hardware
loss (README §10). 2B does **not** attempt anonymous/unlinkable public distribution — see §4 for why
that path is rejected in this build.

---

## 3. Item 2A — Owner keys-to-self (self-share)

### 3.1 Decision

On upload, after producing `file_key`+`meta_key`, the client **wraps them to the owner's own X25519
public key** using the existing `wrap_file_keys` path and uploads the bundle as a **self-share row**
(owner shared with owner). `get_wrapped_keys` then returns a bundle for the owner exactly as for any
recipient. The plaintext `<file_id>.keys.json` cache and the `--key-cache` options are **removed**.
There is then **one** key-acquisition path for download and share: fetch the bundle, unwrap with the
owner's X25519 private key.

Rationale: the local cache is the only place in the whole system where `file_key`/`meta_key` sit in
plaintext at rest (`client/cli.py:275-282`); eliminating it removes T-2A entirely and collapses the
two-branch download logic (`client/cli.py:351-378`) into one. It reuses the audited wrap path with
zero new crypto.

### 3.2 Storage

No new table. A self-share is a row in the existing `file_shares`
(`server/database.py:88-94`) with `shared_with_id == owner_id`. `get_wrapped_keys(file_id, user_id)`
(`server/database.py:693-701`) already returns the right row for any `user_id`, including the owner.

Constraint honored: **"no server-side caching of wrapped keys beyond stored share rows."** The
self-share *is* a stored share row; nothing is cached transiently.

`PRIMARY KEY (file_id, shared_with_id)` already permits one row per (file, user); the owner's row
coexists with recipients' rows. No schema change for 2A.

### 3.3 Wrap binding for the self-share

The wrap binds the **sender's Ed25519 identity** into HKDF info and AEAD AAD
(`wrapping.rs:248-259`, `283-301`). For a self-share, sender == recipient == owner. The owner's
own Ed25519 public key is the `sender_identity_pub`; the owner's X25519 key is the recipient. On
unwrap, the client passes the owner's own Ed25519 key as `sender_pubkey`. This is already supported
by `KeyStore.unwrap_file_keys` (`client/keystore.py:221-246`) — the keystore unwraps with its own
X25519 private key and the caller supplies the claimed sender Ed25519 key.

### 3.4 Unified key-acquisition path (client)

A single helper replaces the fork at `client/cli.py:347-378`:

```
acquire_file_keys(client, keystore, file_id_bytes, header) -> (file_key, meta_key, signer_ed25519):
    wrapped = client.get_wrapped_keys(file_id_hex)        # /api/files/<id>/wrapped_keys
    if wrapped is None:
        raise CryptoError("No wrapped keys for this file and user")   # fail-closed
    signer_ed25519 = client.get_owner_pubkey(file_id_hex)  # owner's pinned Ed25519
    if signer_ed25519 is None or len(signer_ed25519) != 32:
        raise CryptoError("Owner has no registered identity key; cannot verify")
    file_key, meta_key = keystore.unwrap_file_keys(
        wrapped, file_id_bytes, sender_pubkey=signer_ed25519)
    return file_key, meta_key, signer_ed25519
```

For both owner and recipient the `signer_ed25519` used to *verify the Merkle signature* is the
**owner's** Ed25519 key (the file was signed by the owner at encrypt time,
`client/encryptor.py:180-188`). For a self-share, owner==recipient, so `get_owner_pubkey` returns
the caller's own key — and the wrap's `sender_identity_pub` is that same key. Consistent.

Edge case: the owner must have registered an X25519 key (2C) **before** their first upload, because
upload now needs the owner's X25519 public key to self-wrap. The keystore already has it
(`client/keystore.py:158-165`); no server round-trip is needed to self-wrap (the client reads its
own `x25519_public_key()`). So 2A's self-wrap has **no dependency on the directory** — the client
wraps to a key it already holds locally. The directory (2C) is only needed to wrap to *other*
recipients (2B and `share`).

### 3.5 Upload flow (2A)

```
client.upload(path, visibility):
    ks.unlock(pw)
    enc = encryptor.encrypt_file(...)           # file_key, meta_key, header, enc_meta
    upload_id = client.upload_init(...)
    for idx, blob in chunks: client.upload_chunk(...)
    file_id = client.upload_finalize(...)        # server stores ciphertext + visibility
    # --- 2A: self-wrap and register the owner's bundle ---
    own_x = ks.x25519_public_key()
    own_ed = ks.ed25519_public_key()
    self_bundle = ks.wrap_file_keys(enc.file_key, enc.meta_key, file_id_bytes,
                                    recipient_pubkey=own_x)   # sender_id = own_ed (internal)
    client.register_self_keys(file_id, self_bundle)          # NEW endpoint, see §3.6
    # NO keys.json written.
```

The self-share registration is a distinct endpoint from `/share` because `/share` is timing-
equalized against an *external* username oracle (`server/storage.py:1042-1107`); registering a
bundle to *yourself* has no username to enumerate and should not pay the 150 ms budget. See §3.6.

### 3.6 New endpoint: register owner self-keys

```
POST /api/files/<file_id>/self_keys      (auth required; owner only)
  body  {"wrapped_keys": <hex>}          # 136-byte self-share bundle (hex)
  200   {"status": "stored"}
  404   {"error": "Not found"}           # not owner / unknown file (uniform with other endpoints)
  400   {"error": "Invalid request"}     # bad length / hex
```

Server handler (mirrors `share_file` ownership check at `server/storage.py:1002-1007`, but **no
timing budget and no username branch**):

```
self_keys(file_id):
    file_id = _validate_id(file_id)                      # 404 on bad format
    check_file_ownership(db, file_id, identity.user_id)  # AuthError -> 404
    wrapped = bytes.fromhex(body["wrapped_keys"])        # 400 on bad hex
    if not (MIN_WRAPPED_KEYS_BYTES <= len(wrapped) <= MAX_WRAPPED_KEYS_BYTES): 400
    with db.transaction():
        db.add_file_share(file_id, identity.user_id, wrapped)   # shared_with == owner
    return {"status": "stored"}, 200
```

Why not reuse `POST /share` with `shared_with = own username`? `share_file` explicitly treats a
self-share as `is_self_share` and routes it to the **dummy no-op branch**
(`server/storage.py:1053-1056`, `1080-1094`) — it deliberately does *not* write a row for yourself.
Changing that would couple the self-keys flow to the timing-oracle machinery. A dedicated endpoint
is cleaner and keeps `/share`'s security property intact.

Idempotency: `add_file_share` is `INSERT OR REPLACE` (`server/database.py:640-645`), so re-running
upload-repair or re-registering is safe.

### 3.7 Migration / retirement of existing keys.json

Existing on-disk caches must be retired without losing access to already-uploaded files.

- **New CLI subcommand `localcloud migrate-keys`** (one-shot, opt-in):
  1. `ks.unlock(pw)`.
  2. Glob `~/.localcloud/*.keys.json` (and any `--key-cache` paths the user names).
  3. For each: parse `{file_id, file_key, meta_key}` (`_load_owner_key_cache`,
     `client/cli.py:597-605`); wrap to the owner's own X25519 key; `POST .../self_keys`.
  4. On success, **shred-and-unlink** the JSON (best-effort overwrite then `os.unlink`; the file is
     mode 0600 already).
  5. Print a summary; never delete a file whose upload to `self_keys` failed (fail-closed).
- `upload`, `download`, `share` **stop reading or writing** `keys.json`. `download`/`share` always
  use the unified acquisition path (§3.4) and `self_keys` registration (§3.5).
- The `--key-cache` option is removed from `upload`/`download`/`share`
  (`client/cli.py:181-189`, `303-307`, `481-485`). This is a **CLI breaking change** (BC-3).

Operator/owner note: a file uploaded under Phase 1 whose `keys.json` was already lost is
**unrecoverable** (no plaintext keys anywhere) — this is by design and unchanged. `migrate-keys`
only helps where the cache still exists.

---

## 4. Item 2B — Public-visibility key delivery

### 4.1 Decision

Adopt baseline **(iii): per-recipient wrap to every ENROLLED user at publish time.** "Publish" (set
visibility=public, or share-as-public) wraps `file_key`+`meta_key` once per enrolled user (those who
have a directory entry with a valid, self-signed X25519 key) and stores one share row each. Downloads
then go through the **same** `get_wrapped_keys` path as private/shared files. Nothing new is cached
server-side beyond the stored share rows.

This is the recommended baseline from the prior review; the security argument and the rejection of
(i) and (ii) follow.

### 4.2 Why (iii) and not (ii) request/grant

Option (ii) — recipient requests, owner grants on demand — **requires the owner to be online** to
wrap keys for each new reader. README PART II §1-2 explicitly designs the server to be **offline on a
schedule and instantly killable**, and §10 treats the owner as frequently offline. An offline owner
means public files become unreadable to new readers until the owner returns — that is not "public."
(ii) also reintroduces an interactive protocol and a request queue the hostile server mediates,
expanding attack surface. **Rejected: unsound for an offline owner.**

### 4.3 Why not (i) anonymous / single-bundle multi-recipient

A single ciphertext bundle decryptable by many recipients (e.g. a KEM-per-recipient envelope around
one content-encryption key, or a broadcast scheme) is attractive for fanout but is **rejected in
this build** for three concrete reasons:

1. **Key-commitment / partitioning-oracle risk.** XChaCha20-Poly1305 (the AEAD everywhere here:
   `shared/crypto.py`, `wrapping.rs:25-28`) is **not key-committing**. A multi-recipient construction
   in which the same ciphertext is opened under recipient-specific derived keys is exactly the shape
   that enables a **partitioning oracle**: an adversary who can submit candidate keys/bundles and
   observe accept/reject can binary-search the key space far faster than brute force. Safely doing
   (i) would **require adding a key-commitment construction** (e.g. a committing AEAD or an explicit
   commitment hash bound into the envelope) — a **new primitive**, which violates invariant 3 and the
   master rule (README §10: "must not implement custom cryptographic primitives").
2. **New wrap domain + fanout/DoS bounds.** (i) would need a separate `...-public-v1` wrap domain
   (distinct from `localcloud-file-wrap-v2`, `wrapping.rs:40`) and its own analysis of wrap-fanout
   and DoS bounds — additional spec and audit surface.
3. **No anonymity benefit in this deployment.** The server already sees the filename, the owner, the
   visibility flag, and (via WireGuard peer + auth) *who downloads each chunk*
   (`server/storage.py:805-855` requires auth and a peer). An anonymous/unlinkable key envelope buys
   nothing while the access pattern is fully observable. The leakage (iii) adds over (i) — the
   *enrolled-recipient set at publish time* — is small relative to what the server already learns
   from download access patterns.

**Rejected: would require a key-commitment construction (new primitive) and a new wrap domain, for
no anonymity gain under this threat model.** If anonymous public distribution ever becomes a
requirement, it is a separate, security-reviewed work item with a committing-AEAD design — recorded
as an open question (§11).

### 4.4 What "public" concretely means in this build

> **Public file = a file whose `file_key`/`meta_key` are wrapped, at publish time, to every user
> who is enrolled in the directory (has a valid self-signed X25519 key) at that moment, plus the
> owner. The server authorizes ciphertext access to any authenticated user (unchanged policy,
> `server/policy.py:37-38`), and a wrapped bundle exists for exactly the set of users present and
> enrolled at publish time.**

Consequences, stated plainly:

- A user enrolled at publish time can read the file (bundle exists).
- A user **not** enrolled at publish time can fetch ciphertext (policy allows it) but **cannot
  decrypt** — `get_wrapped_keys` returns `null`, and the client **fails closed** (§3.4). This is
  acceptable and correct: "public" here means "published to the current enrolled population," not
  "world-readable forever to anyone who ever joins."
- This keeps the system honest about forward secrecy: there is no long-lived global key and no
  server-held decryptable material beyond per-recipient bundles.

### 4.5 How a new enrollee gets keys for already-public files (T-N4)

A user who enrolls after publication has **no** bundle. Two defined, non-automatic mechanisms:

1. **Owner re-publish (authoritative).** The owner runs `localcloud publish <file_id>` again (or a
   dedicated `localcloud republish <file_id>`); the client re-fetches the current enrolled set from
   the directory and wraps to any users missing a row (idempotent `INSERT OR REPLACE`). This admits
   newly-enrolled users.
2. **No silent server-side grant.** The server must never synthesize or copy a bundle for a new user
   — it has no plaintext keys to wrap and must not move bundles between users (a bundle is bound to
   one recipient's X25519 key via AAD, `wrapping.rs:283-301`, so copying is useless anyway).

This is intentional: the owner controls the audience; enrollment after the fact does not
retroactively grant access without the owner re-publishing. Documented for the owner in §11.

### 4.6 Publish flow (2B)

```
client.publish(file_id):                    # owner only; sets/keeps visibility=public
    ks.unlock(pw)
    file_key, meta_key, _ = acquire_file_keys(client, ks, file_id_bytes, header)  # from own self-share
    enrolled = client.directory_list_enrolled()      # NEW endpoint §5C: [{username, x25519, ed25519, self_sig}]
    if len(enrolled) > MAX_PUBLISH_FANOUT: abort      # DoS bound, §7
    for entry in enrolled:
        verify_x25519_self_sig(entry)                 # MANDATORY, §5C — skip+warn on failure
        bundle = ks.wrap_file_keys(file_key, meta_key, file_id_bytes, entry.x25519)
        client.share_file(file_id, entry.username, bundle)   # reuses /share (writes a row)
    client.set_visibility(file_id, PUBLIC)            # see §4.7
```

Notes:
- The owner must be able to decrypt the file first (self-share from 2A) to obtain the keys to
  re-wrap. This is why 2A is sequenced before 2B (§10).
- Each per-recipient wrap reuses `wrapping.rs` **unchanged** (invariant 3).
- `verify_x25519_self_sig` failure for an entry => **skip that recipient and warn**, do not abort
  the whole publish (a single malformed directory entry, possibly server-injected, must not deny
  publication to everyone else). This is fail-closed *per recipient* (no bundle for the bad entry).

### 4.7 Server side for 2B

2B needs **no new server crypto**. It uses:
- `POST /api/files/<id>/share` (`server/storage.py:983-1107`) to store each per-recipient bundle.
- A way to set visibility=public on an existing file. Today visibility is fixed at finalize
  (`server/storage.py:549-554`, `674-683`) and only ever *raised* to SHARED by `/share`
  (`server/storage.py:1076-1079`). **Add** a minimal owner-only endpoint:

```
PUT /api/files/<file_id>/visibility       (auth; owner only)
  body  {"visibility": 2}                  # only 1->2 or 0->2 elevation permitted; never lower here
  200   {"status": "updated"}
  404   not owner / unknown                 # uniform
  400   invalid value / illegal transition
```

Rationale for a separate endpoint rather than overloading `/share`: making a file public is a
distinct authorization decision from sharing with one user, and conflating them inside the timing-
equalized `/share` handler is error-prone. Visibility lowering (public→private) remains out of scope
for this item (it would orphan reader bundles; tracked as an open question §11).

Constraint honored: **no server-side caching of wrapped keys beyond stored share rows.** Every
bundle 2B creates is a normal `file_shares` row. The server stores nothing else.

### 4.8 Leakage trade-offs (2B), explicit

| Leakage | (iii) per-recipient (chosen) | (i) anonymous multi-recipient (rejected) |
|---|---|---|
| Enrolled-recipient set at publish | **Visible** (one row per enrollee) | Hidden |
| Per-download identity | Visible (auth+peer) — same in both | Visible — same in both |
| Wrap-fanout cost | O(enrolled), bounded (§7) | O(1) |
| Requires new primitive | **No** (reuses audited wrap) | **Yes** (committing AEAD) |
| Key-commitment / partitioning-oracle exposure | **None** (each bundle one recipient) | Present unless committed |

The accepted cost of (iii) is the enrolled-set disclosure and fanout. Given the server already
observes download access patterns, this is the right trade for a build that forbids new primitives.

---

## 5. Item 2C — Pubkey enrollment & directory (schema v6)

### 5.1 Decision

Store the user's **X25519 public key** server-side alongside Ed25519, **plus an Ed25519
self-signature over the X25519 key**. Provide a directory-lookup API. The sharer/publisher **MUST
verify the self-signature before wrapping**, so that pinning the Ed25519 fingerprint out-of-band
transitively authenticates the X25519 key. The lookup returns a **uniform response** for
unknown-vs-keyless users (no enumeration oracle).

### 5.2 Self-signature construction (new signed object)

A new domain-separated signing input, distinct from the Merkle context (`shared/models.py:96`,
`MERKLE_SIG_CONTEXT = b"localcloud-merkle-v2"`):

```
ENROLL_SIG_CONTEXT = b"localcloud-x25519-enroll-v1"

enroll_signing_input(x25519_pub: 32) =
    ENROLL_SIG_CONTEXT
      || username_canonical_utf8_len (u16 big-endian)
      || username_canonical (UTF-8, NFKC+casefold, the server-canonical form)
      || x25519_pub (32 bytes)
```

- Signed with the user's **Ed25519 private key**; verified with their Ed25519 public key.
- Domain tag prevents cross-protocol replay (T-N3): a Merkle-root signature can never satisfy this
  verifier and vice-versa (distinct context prefixes, distinct lengths).
- Binding the **canonical username** into the signed input ties the X25519 key to the account it is
  enrolled under, so a server cannot lift Alice's self-signed key onto Bob's row. The canonical form
  is exactly `_canonicalize_username` (`server/auth.py:103-125`); the client must canonicalize
  identically before signing. (Implementation note: the client computes the same NFKC+casefold+strip;
  this normalization MUST be shared, not re-implemented — see task T-2C.1.)
- Length-prefixing the username makes the concatenation unambiguous.

Keycore already exposes `sign` and `verify_signature` (`rust/keycore/src/lib.rs:85-89`, `163-175`);
**no Rust change is required** — the signing input is built in Python and passed to `ks.sign(...)`,
and verified via `keycore.verify_signature(...)`. (This mirrors how the Merkle signature is built and
verified in Python today, `client/encryptor.py:180-188`, `client/encryptor.py:334`.)

### 5.3 Schema v6 DDL + migration

Add two columns to `users` and bump `SCHEMA_VERSION` to 6 (`server/database.py:19`). Follow the
existing idempotent ALTER pattern (`server/database.py:148-164`, `265-291`).

**`SCHEMA_SQL` users table additions** (so fresh DBs get them directly):

```sql
-- Long-term X25519 key-agreement public key (32 bytes). Empty until the
-- user enrolls. Used by sharers/publishers to wrap file keys to this user.
x25519_pubkey BLOB NOT NULL DEFAULT x'',
-- Ed25519 self-signature (64 bytes) over enroll_signing_input(x25519_pubkey).
-- Lets a sharer who pinned this user's Ed25519 fingerprint verify the
-- X25519 key transitively. Empty until enrollment.
x25519_self_sig BLOB NOT NULL DEFAULT x'',
```

**`MIGRATION_V5_TO_V6`** (idempotent via the duplicate-column catch, `server/database.py:167-174`):

```sql
ALTER TABLE users ADD COLUMN x25519_pubkey BLOB NOT NULL DEFAULT x'';
ALTER TABLE users ADD COLUMN x25519_self_sig BLOB NOT NULL DEFAULT x'';
```

**Migration runner** — extend the chain in `_init_schema` (`server/database.py:286-291`):

```
if current < 6:
    try:
        self._conn.executescript(MIGRATION_V5_TO_V6)
    except sqlite3.OperationalError as exc:
        if not _is_duplicate_column_error(exc):
            raise
    current = 6
```

Existing v5 rows migrate with empty X25519 key + empty self-sig — i.e. **not enrolled**. They show
up in the directory as keyless (uniform response, §5.4) and are skipped by publish fanout until they
enroll. No data loss; no downtime beyond the single ALTER pass (matches v3→v4 which also added a
`users` BLOB column, `server/database.py:148-153`).

### 5.4 Enrollment flow

Enrollment is **client-initiated over the authenticated tunnel** (unlike `register-pubkey` for
Ed25519, which is an operator step today, `server/admin.py:100-133`). The X25519 key + self-sig are
self-authenticating (the self-sig is verifiable against the already-registered Ed25519 key), so the
server can accept them from the user without operator mediation, **provided the user's Ed25519 key is
already registered** by the operator (the chain root stays operator-controlled).

```
POST /api/users/enroll_x25519            (auth required; acts on the caller's own row)
  body  {"x25519_pubkey": <hex 32>, "self_sig": <hex 64>}
  200   {"status": "enrolled"}
  400   {"error": "Invalid request"}     # bad length/hex, OR self-sig fails against caller's Ed25519
  409   {"error": "No identity key"}     # caller has no Ed25519 registered yet (operator must do it)
```

Server handler:

```
enroll_x25519():
    x = bytes.fromhex(body["x25519_pubkey"]); sig = bytes.fromhex(body["self_sig"])   # 400 on bad hex
    if len(x) != 32 or len(sig) != 64: 400
    user = db.get_user_by_id(identity.user_id)
    ed = user["ed25519_pubkey"]
    if not ed: 409                                   # chain root not established yet
    msg = enroll_signing_input(x, canonical_username = identity.username)
    if not verify_ed25519(ed, msg, sig): 400         # server verifies self-sig too (defense in depth)
    with db.transaction():
        db.set_x25519(identity.user_id, x, sig)       # new DB method
    return {"status": "enrolled"}, 200
```

The server verifying the self-sig is **defense in depth** — the security property does not rest on
the server (it is hostile); it rests on the *sharer* re-verifying (§5.5). But having the server
reject a malformed self-sig keeps the directory clean and avoids storing junk.

Client `localcloud enroll`:

```
localcloud enroll:
    ks.unlock(pw)
    x = ks.x25519_public_key(); 
    msg = enroll_signing_input(x, canonical_username = <my canonical username>)
    sig = ks.sign(msg)
    client.enroll_x25519(x, sig)
```

The user still hands their Ed25519 key to the operator for `register-pubkey`
(`server/admin.py:100-133`) once; thereafter X25519 enrollment is self-service. (Alternative:
operator also sets X25519 via a new admin subcommand `enroll-x25519 <user> <x_hex> <sig_hex>`;
recorded as an optional convenience in tasks, not required.)

### 5.5 Directory lookup API + MANDATORY sharer verification

```
GET /api/users/<username>/pubkeys         (auth required)
  200 ALWAYS (uniform — no enumeration oracle, T-N2):
      {"ed25519": <hex or "">, "x25519": <hex or "">, "self_sig": <hex or "">}
```

- **Uniform response:** unknown user, keyless user, and not-yet-enrolled user all return `200` with
  empty strings for the missing fields. The handler must do **equivalent work** in all cases (a row
  fetch that touches the same columns, or a constant-shape dummy) so existence is not timing-
  distinguishable — same discipline as `share_file` (`server/storage.py:1042-1052`). A simpler and
  robust choice: always `SELECT ed25519_pubkey, x25519_pubkey, x25519_self_sig` by canonical
  username; if no row, return all-empty. The lookup touches at most one row either way; to be safe
  against the "row exists vs not" delta noted in Round-7 M3, the implementer SHOULD add a small
  constant-deadline envelope mirroring `_SHARE_TIMING_BUDGET_S` if measurement shows a delta. (Task
  T-2C.5 includes a timing assertion.)
- **Canonicalization:** `<username>` is canonicalized server-side (`_canonicalize_username`) before
  lookup so `Alice`/`ＡＬＩＣＥ`/`alice` all resolve to the same row (matches `share_file`,
  `server/storage.py:1023-1028`). A username that fails canonicalization returns the same all-empty
  `200`.

**MANDATORY client-side verification before any wrap** (this is the whole security point of 2C):

```
verify_x25519_self_sig(entry) -> x25519_bytes:    # raises on failure
    if not entry.ed25519 or not entry.x25519 or not entry.self_sig:
        raise CryptoError("recipient not enrolled")          # fail-closed
    # OUT-OF-BAND PIN CHECK (when sharing with a specific person):
    #   the operator/user has the recipient's Ed25519 fingerprint pinned;
    #   compare entry.ed25519 against the pinned value. If it mismatches, ABORT.
    msg = enroll_signing_input(entry.x25519, canonical_username = entry.username)
    if not keycore.verify_signature(entry.ed25519, msg, entry.self_sig):
        raise CryptoError("X25519 self-signature invalid")   # fail-closed
    return entry.x25519
```

Trust chain, explicitly: the hostile server can lie about *any* field. But if the user has pinned
the recipient's **Ed25519 fingerprint** out-of-band (the existing TOFU model, `client/cli.py:147-171`,
README §6), then:
- A substituted `ed25519` is caught by the pin check.
- A substituted `x25519` (with the real `ed25519`) fails `verify_signature` because the server cannot
  forge an Ed25519 self-signature without the recipient's private key.
- Therefore a verified `(ed25519, x25519, self_sig)` triple authenticates the X25519 key **as
  strongly as the Ed25519 pin** — substitution is impossible. This is exactly the transitive
  authentication the task requires.

For **public publish** (2B) there is generally no per-recipient out-of-band pin; the publisher relies
on the self-signature alone (it still defeats a server that substitutes X25519 while keeping a
victim's real Ed25519, because the server can't forge the self-sig). The residual trust is that the
*directory population* is honest about *which Ed25519 keys exist* — which is the same trust already
placed in `register-pubkey`/`owner_pubkey` today (`server/storage.py:773-802`). No regression.

### 5.6 New DB methods (database.py)

```
set_x25519(user_id, x25519_pubkey: bytes, self_sig: bytes) -> None      # within a transaction
get_pubkeys_by_username(username_canonical) -> dict | None
    # returns {"ed25519":bytes, "x25519":bytes, "self_sig":bytes} or None
list_enrolled_users(limit, offset) -> list[dict]
    # rows where x25519_pubkey != x'' : [{username, ed25519, x25519, self_sig}]
```

`list_enrolled_users` backs the publish fanout (§4.6) and a directory-list endpoint:

```
GET /api/users/enrolled?limit=&offset=    (auth required)
  200 {"users":[{"username","ed25519":<hex>,"x25519":<hex>,"self_sig":<hex>}], "limit","offset"}
```

Pagination bounds mirror `list_files` (`server/storage.py:944-945`, max 200). The publisher pages
through until exhausted, capped by `MAX_PUBLISH_FANOUT` (§7).

Privacy note: `enrolled` lists usernames + public keys to any authenticated user. This is the same
disclosure class as `list_files` exposing public-file owners, and is inherent to a directory. The
keys are public by definition. Recorded as accepted leakage.

---

## 6. Item 2D — Bind metadata to file version (wire change)

### 6.1 Decision

Include **`merkle_root` (32 bytes) only** — **not** the signature — in the metadata blob's AAD, so
the encrypted metadata is cryptographically pinned to exactly one file version. Bump
`PROTOCOL_VERSION` 1→2. Provide a migration so already-stored v1 files still decrypt.

`merkle_root` is the right binder because it is the unique fingerprint of the file's chunk set
(`client/encryptor.py:177`), and it is already what the Ed25519 signature covers
(`shared/models.py:99-139`). Including the signature would be redundant (the signature is over the
root) and would needlessly couple the AEAD to a 64-byte field that adds no information beyond the
root. **`merkle_root` only.**

### 6.2 The no-circular-dependency invariant (confirmed)

> **INVARIANT (record and keep): the metadata AAD MAY depend on `merkle_root`, but the Merkle tree
> MUST NEVER depend on the metadata ciphertext.**

Confirmed against current code: `encrypt_file` computes `chunk_hashes` from the **data chunks only**
(`client/encryptor.py:150-171`), builds the Merkle root from those (`client/encryptor.py:177`), then
encrypts the metadata **afterward** (`client/encryptor.py:199-217`). The metadata blob is **not** a
Merkle leaf and never enters `merkle_root(...)`. Therefore making the metadata AAD depend on
`merkle_root` introduces **no cycle**. The implementer MUST keep this ordering:
**(1) hash chunks → (2) compute root → (3) encrypt metadata with AAD that includes the root.**
A property test will assert the root is independent of the metadata ciphertext (task T-2D.4).

### 6.3 New metadata-AAD construction

The metadata AAD is currently produced by `ChunkAAD(file_id, METADATA_CHUNK_INDEX,
total_chunks=0).serialize()` — a fixed `>16sIHI` struct (`client/encryptor.py:211-216`,
`shared/models.py:394-417`, `client/encryptor.py:498-502`). The struct packing is fixed-width and has
no room for a 32-byte root, and `ChunkAAD` is also used for *data* chunks (which must not gain a root
field). So introduce a **dedicated metadata-AAD builder** in `shared/models.py`, leaving `ChunkAAD`
untouched:

```
METADATA_AAD_CONTEXT = b"localcloud-meta-aad-v2"      # new domain tag; "v2" tracks PROTOCOL_VERSION 2

build_metadata_aad(file_id: 16, merkle_root: 32, protocol_version: int) -> bytes:
    assert len(file_id) == FILE_ID_LEN
    assert len(merkle_root) == BLAKE2B_DIGEST_LEN
    return (
        METADATA_AAD_CONTEXT
          || file_id (16)
          || merkle_root (32)
          || struct.pack(">H", protocol_version)        # u16, matches header.version width
    )
```

- New domain tag `localcloud-meta-aad-v2` ensures a v1 metadata blob can never verify under a v2 AAD
  and vice-versa — the version split is itself enforced by the tag, exactly like the wrap-AAD bump
  (`wrapping.rs:42-45`) and the Merkle context bump (`shared/models.py:93-96`).
- `protocol_version` is included so a future bump again forces non-interoperability (defense in
  depth; the tag already does this, but the explicit field matches the Merkle signing input's style,
  `shared/models.py:134-139`).
- The metadata sentinel index (`METADATA_CHUNK_INDEX`, `shared/models.py:83`) is **retired from the
  metadata AAD** under v2 because the dedicated domain tag now provides the data-vs-metadata
  separation that the sentinel provided under v1. The sentinel constant and its invariant assertions
  (`shared/models.py:375-378`) **remain** (they still document the u32 packing bound for `ChunkAAD`);
  only the metadata path stops using `ChunkAAD`. (Implementer: do not delete the sentinel; it is
  load-bearing for the `ChunkAAD` width invariant.)

### 6.4 Encrypt / decrypt changes

**Encrypt** (`client/encryptor.py:211-216`): replace the `meta_aad = ChunkAAD(...).serialize()` with
`meta_aad = build_metadata_aad(file_id, root, PROTOCOL_VERSION)`. `root` is already in scope
(computed at line 177). Ordering invariant (§6.2) is already satisfied.

**Decrypt** (`client/encryptor.py:349`, `498-502`): `decrypt_metadata` must take `merkle_root` so it
can rebuild the AAD. The metadata is decrypted at `client/encryptor.py:349` **after** the header is
parsed (`merkle_root` available) and **after** the signature verifies (`client/encryptor.py:331-344`)
— so the root used for the AAD is an **authenticated** root, not an attacker-chosen one. New
signature:

```
decrypt_metadata(encrypted_metadata, meta_key, file_id, merkle_root, protocol_version) -> MetadataBlob
    ...
    aad = build_metadata_aad(file_id, merkle_root, protocol_version)
    padded = decrypt_chunk(meta_key, nonce, ciphertext, aad)
    ...
```

This is a **public function signature change** (`decrypt_metadata` is called from `cli` indirectly
via `decrypt_file`, and directly in tests `tests/test_encryptor.py:188`). It is a hard-stop API change
requiring approval (BC-2 / see §9), and tests that call it must be updated as part of the same
approved change (per the test-modification policy, this is a deliberate, flagged signature change, not
"editing a test to make it pass").

### 6.5 PROTOCOL_VERSION bump and its blast radius

`PROTOCOL_VERSION: int = 1 → 2` (`shared/models.py:21`). This value flows into:
- `FileHeader.version` and `FileHeader.validate()` which **rejects** any version != `PROTOCOL_VERSION`
  (`shared/models.py:339-340`). So a v2 client will **reject v1 headers** outright on decrypt.
- `ChunkAAD.protocol_version` default and the per-chunk AAD (`shared/models.py:391`,
  `client/encryptor.py:162-166`) — v2 chunks bind version 2; v1 chunks bind version 1; cross-version
  chunk substitution already fails via AAD.
- `build_merkle_signing_input(..., protocol_version=...)` (`client/encryptor.py:186`,
  `shared/models.py:99-139`) — v2 signatures cover version 2; a v1 signature cannot replay on a v2
  header (different signed input) and vice-versa.

Net effect: **a v2 client cannot read v1 files and a v1 client cannot read v2 files** without the
migration below. This is the intended, clean break — but it means existing data needs a path.

### 6.6 Migration for already-stored files

The server stores ciphertext + header + encrypted metadata opaquely; it cannot re-encrypt (no keys).
Migration is therefore **client-side**, and there are two supported strategies. **Decision: support
both, prefer (B) re-encrypt for active files; offer (A) compatibility-read for download-only.**

- **(A) Compatibility read path (read-only v1 support).** The decrypt path branches on
  `header.version`:
  - If `header.version == 1`: build the **legacy** metadata AAD the old way (`ChunkAAD(file_id,
    METADATA_CHUNK_INDEX, 0)`), verify the v1 Merkle signing input, and accept the file. This
    requires `FileHeader.validate()` to accept `version in {1, 2}` (a small, explicit relaxation:
    introduce `SUPPORTED_VERSIONS = frozenset({1, 2})` and a `MIN/MAX` check instead of the single-
    value equality at `shared/models.py:339-340`). The chunk/Merkle/signature logic is selected by
    version. This lets a v2 client **read** old uploads without re-uploading.
  - The metadata-version binding (2D's whole point) is **only** enforced for v2 files; v1 files retain
    their weaker (no-root) binding. That is acceptable because v1 files predate the fix; the owner can
    upgrade them via (B).
- **(B) Re-encrypt on next write (forward migration).** A `localcloud reupload <file_id> <path>` (or
  the natural next `upload` of a new version once version history lands) re-encrypts under v2,
  producing a v2 header + root-bound metadata, and a new `file_id`/blob. Old v1 blob can then be
  `rm`'d. This fully migrates the file to the v2 guarantee.

Either way, **no stored file becomes unreadable** at the moment of the version bump: (A) keeps v1
readable, (B) upgrades on the owner's schedule. The implementer MUST gate (A) behind explicit
`SUPPORTED_VERSIONS` membership so an *unknown* version (e.g. 3) is still hard-rejected.

(If the owner prefers a hard cutover with no v1 support, (A) can be omitted and `validate()` kept at
`== PROTOCOL_VERSION`; then all pre-existing files must be re-uploaded. This is an **open question for
the owner**, §11 — the default recommendation is to ship (A) for a smooth transition.)

---

## 7. Wrap-fanout & DoS bounds (2B/2C)

- `MAX_PUBLISH_FANOUT` (client-side constant, recommend **1024**): the publish flow refuses to wrap
  to more than this many recipients in one operation, bounding client CPU and the number of share
  rows a single publish creates. Above it, the owner is told to contact the operator (the directory
  is larger than a single publish should fan out to). This is a *client* guard; the server already
  bounds per-request work via `MAX_CONTENT_LENGTH` and per-row inserts.
- Directory `enrolled` endpoint paginates (max 200/page, mirroring `list_files`), so listing the
  population is itself bounded per request.
- `enroll_x25519` is one row write per call, rate-limited by the existing auth/session machinery
  (every endpoint is behind `require_auth`, `server/auth.py:771`).
- Share-row growth from publishing: O(enrolled) rows per public file. With `MAX_PUBLISH_FANOUT=1024`
  and the per-user quota model, this is bounded and accounted as metadata, not ciphertext (share rows
  hold a 136-byte bundle each). If this becomes a storage concern, a future item can move public
  delivery to a committing-AEAD single-bundle scheme (the rejected (i), reconsidered with the
  required primitive) — recorded as an open question (§11).

---

## 8. Consolidated leakage / threat analysis

| ID | Vector | Before Phase 2 | After Phase 2 | Residual |
|----|--------|----------------|---------------|----------|
| L1 | `file_key`/`meta_key` at rest | Plaintext in `keys.json` (`cli.py:275-282`) | Only in password-encrypted keystore + server bundle wrapped to owner X25519 | Keystore password strength; client compromise (unchanged non-goal) |
| L2 | Server reads file keys | No (wrapped) | No (wrapped); self-share bundle is opaque AEAD | None new |
| L3 | X25519 substitution by server | Possible (out-of-band, unverified) | Defeated by Ed25519 self-sig + OOB Ed25519 pin (§5.5) | Trust in directory's *set* of Ed25519 keys (= same as today's `register-pubkey`) |
| L4 | Public file readable by intended audience | No key delivery | Per-recipient wrapped bundle at publish | New enrollees need re-publish (T-N4, by design) |
| L5 | Enrolled-recipient set of a public file | N/A (no public delivery) | **Visible** to server (one row/enrollee) | Accepted trade vs. new-primitive cost (§4.3, §4.8) |
| L6 | Directory enumeration (user exists?) | N/A | Uniform `200` all-empty for unknown/keyless (§5.5) | Timing delta mitigated by constant-deadline envelope if measured (T-2C.5) |
| L7 | Metadata/version substitution | Possible (AAD lacks root) | Defeated for v2 (root in metadata AAD, §6) | v1 files retain weak binding until re-uploaded (B) |
| L8 | Cross-protocol signature replay | Merkle context only | New `localcloud-x25519-enroll-v1` + `localcloud-meta-aad-v2` domain tags isolate each signed/AEAD object | None |
| L9 | Self-sig lifted onto another account | N/A | Username bound into `enroll_signing_input` (§5.2) | None |
| L10 | Partitioning oracle on public delivery | N/A | **Avoided** by per-recipient wrap (no shared-key AEAD) (§4.3) | None (unless a future (i) scheme is adopted without commitment) |
| L11 | Forward secrecy of bundles | Ephemeral-static (`wrapping.rs:97-101`) | Unchanged; self-share & fanout reuse the same wrap | None new |
| L12 | Fanout DoS | N/A | Bounded by `MAX_PUBLISH_FANOUT` + pagination (§7) | Share-row storage growth (accounted) |

Fail-closed coverage: download with no bundle raises (§3.4); publish skips unverifiable directory
entries per-recipient (§4.6); enroll/self-sig verify failures reject (§5.4-5.5); unknown protocol
version hard-rejects (§6.6). Generic errors preserved on all new endpoints (404 uniform; 400 generic).

---

## 9. Breaking changes (require explicit human approval)

These are HARD STOPS per the project's clarification/dependencies/test policies. Each needs owner
sign-off before 2-impl proceeds.

- **BC-1 — Schema v6.** `SCHEMA_VERSION 5 → 6`; new `users.x25519_pubkey`, `users.x25519_self_sig`
  BLOB columns; new `MIGRATION_V5_TO_V6` + runner branch (`server/database.py:19`, `148-164`,
  `286-291`). Forward-only; v5 rows become "not enrolled." Irreversible once written (a v6 DB will
  fail to open under v5 code via the version-mismatch guard, `server/database.py:296-300`).
- **BC-2 — `PROTOCOL_VERSION 1 → 2` and wire/format changes.** New `METADATA_AAD_CONTEXT`
  (`localcloud-meta-aad-v2`); metadata blob AAD now binds `merkle_root`; `decrypt_metadata` signature
  gains `merkle_root` + `protocol_version`; `FileHeader.validate()` relaxed to `SUPPORTED_VERSIONS`
  (`shared/models.py:21`, `339-340`, `394-417`, `client/encryptor.py:211-216`, `469-506`). v1 and v2
  files are mutually unreadable except via the §6.6(A) compatibility path. **Public API change**
  (`decrypt_metadata`).
- **BC-3 — Removal of the plaintext key cache.** `<file_id>.keys.json` is no longer written or read;
  `--key-cache` options removed from `upload`/`download`/`share` (`client/cli.py:181-189`, `266-284`,
  `303-307`, `363-378`, `481-485`, `517-530`). New `migrate-keys` subcommand to retire existing
  caches (§3.7). **CLI behavior change.**
- **BC-4 — New HTTP endpoints (API additions).** `POST /api/files/<id>/self_keys`,
  `PUT /api/files/<id>/visibility`, `POST /api/users/enroll_x25519`,
  `GET /api/users/<username>/pubkeys`, `GET /api/users/enrolled`. Additive (no existing endpoint
  changes shape), but they widen the server's API surface and need review.
- **BC-5 — New CLI subcommands.** `enroll`, `publish` (and `republish`/`reupload` if adopted),
  `migrate-keys`. Additive.
- **BC-6 — Client `acquire_file_keys` unification** changes the download code path so the owner no
  longer falls back to a local cache (`client/cli.py:347-378`). Behavior change for owned-file
  download (now requires a server self-share bundle to exist; created at upload by 2A, or by
  `migrate-keys` for legacy files).

No new third-party dependency is introduced (all crypto reuses `keycore` + `shared/crypto.py`).
`cargo audit` / `pip-audit` are unaffected because no Rust or Python dependency is added. (If any is
ever proposed, it is its own hard stop per policy.)

---

## 10. Implementation task list for 2-impl (TDD-sized, sequenced)

Order respects dependencies: **2D and 2C-schema are independent and can land first; 2A depends on the
owner having an X25519 key (2C enrollment) only at upload time; 2B depends on 2A (owner must decrypt
to re-wrap) and on 2C (directory).** Each task is "write test → see red → implement → green," with the
project run order `black → isort → ruff → pylint → pyright → pytest` and `cargo test/clippy/fmt` where
Rust is touched (none is, except optional admin convenience).

### Track 2D — metadata/version binding (no schema, no server)
- **T-2D.1** Add `METADATA_AAD_CONTEXT` + `build_metadata_aad(...)` to `shared/models.py` with unit
  tests: fixed length, fields in order, rejects wrong-length `file_id`/`root`. (mirrors
  `build_merkle_signing_input` tests, `shared/models.py:99-139`).
- **T-2D.2** Bump `PROTOCOL_VERSION → 2`; introduce `SUPPORTED_VERSIONS = {1,2}`; relax
  `FileHeader.validate()` to membership; test that version 3 still rejects and version 1/2 accept.
- **T-2D.3** Switch `encrypt_file` metadata AAD to `build_metadata_aad(file_id, root,
  PROTOCOL_VERSION)`; test a full encrypt→decrypt round-trip under v2.
- **T-2D.4** Property test: the Merkle root is byte-identical regardless of metadata content/key
  (encrypt the same chunks with two different metadata blobs; assert equal `header.merkle_root`) —
  pins the no-circular-dependency invariant (§6.2).
- **T-2D.5** Add `merkle_root`+`protocol_version` params to `decrypt_metadata`; thread the
  authenticated root from `decrypt_file` (`client/encryptor.py:349`); update existing direct callers
  in tests (`tests/test_encryptor.py:188`) — flagged as part of BC-2.
- **T-2D.6** Negative test: a v2 metadata blob encrypted under root R fails to decrypt when presented
  with a header carrying root R' (substitution caught) — surfaces as `DecryptionError`.
- **T-2D.7** §6.6(A) compatibility-read: version-branch in `decrypt_file`/`decrypt_metadata` builds
  the legacy AAD for `version==1`; round-trip a synthesized v1 file and assert it still decrypts;
  assert v1 path does **not** require the new root binding.

### Track 2C — enrollment & directory (schema v6 — BC-1)
- **T-2C.1** Shared canonicalization: extract/confirm a single `canonicalize_username` usable by both
  client and server (today it lives in `server/auth.py:103-125` and `server/admin.py:40-49`); ensure
  the client signs over the identical canonical bytes. Unit test parity across NFKC/casefold cases.
- **T-2C.2** Add `ENROLL_SIG_CONTEXT` + `enroll_signing_input(...)` (shared); unit-test format and
  domain separation from `MERKLE_SIG_CONTEXT`.
- **T-2C.3** Schema v6: add columns to `SCHEMA_SQL`, `MIGRATION_V5_TO_V6`, runner branch
  (`server/database.py`). Tests: fresh DB has columns; a synthesized v5 DB migrates idempotently to
  v6 (re-run migration twice — duplicate-column path), preserving existing rows (extend
  `tests/test_database.py` migration-idempotence tests, `tests/test_database.py:4`,`171-188`).
- **T-2C.4** DB methods `set_x25519`, `get_pubkeys_by_username`, `list_enrolled_users`; unit tests
  including the keyless/unknown cases returning empty/None.
- **T-2C.5** Endpoints `POST /api/users/enroll_x25519`, `GET /api/users/<u>/pubkeys`,
  `GET /api/users/enrolled`. Tests: enroll happy path; enroll rejects bad self-sig (400); enroll 409
  when no Ed25519; **directory uniform-response test** (unknown vs keyless vs enrolled all 200, same
  shape); a timing-equality assertion (or constant-deadline envelope if a delta is measured), modeled
  on `tests/test_storage_share.py`.
- **T-2C.6** Client `enroll` command + `api_client` methods (`enroll_x25519`, `get_pubkeys`,
  `directory_list_enrolled`); `verify_x25519_self_sig` helper with fail-closed tests (missing fields,
  bad sig, good sig). (Optional T-2C.6b: admin `enroll-x25519` convenience subcommand.)

### Track 2A — owner self-share (depends on 2C enrollment existing for the owner)
- **T-2A.1** Server `POST /api/files/<id>/self_keys` (owner-only, no timing budget); tests: owner
  stores bundle; non-owner → 404; bad length → 400; idempotent re-store (extend
  `tests/test_storage_share.py`).
- **T-2A.2** Client `api_client.register_self_keys`; wire into `upload` after finalize; assert a
  self-share row exists after upload and `get_wrapped_keys` returns it for the owner.
- **T-2A.3** Implement unified `acquire_file_keys` (§3.4); refactor `download` to use it; **remove**
  the `keys.json` read branch (`client/cli.py:363-378`). Tests: owner downloads via self-share
  bundle; download fails closed when no bundle (no cache fallback).
- **T-2A.4** Remove `keys.json` write + `--key-cache` from `upload`/`download`/`share`; update
  `share` to acquire keys via the self-share bundle instead of the cache
  (`client/cli.py:517-530`). Tests: `share` works with no cache present.
- **T-2A.5** `localcloud migrate-keys` (§3.7): wrap each cached file to self, register, shred-unlink.
  Tests with a `tmp_path` fake home containing a legacy `keys.json` (deterministic; no network — mock
  the `api_client` at the HTTP boundary only).

### Track 2B — public delivery (depends on 2A + 2C)
- **T-2B.1** Server `PUT /api/files/<id>/visibility` (owner-only; elevation-only). Tests: owner
  raises private→public; non-owner → 404; illegal/lower transition → 400.
- **T-2B.2** Client `publish` command (§4.6): acquire keys from self-share, list enrolled, verify each
  self-sig, wrap per recipient via `/share`, set visibility. Tests: publishing to N enrolled users
  creates N share rows + owner row; a directory entry with a bad self-sig is skipped (warned), others
  still get rows; `MAX_PUBLISH_FANOUT` enforced.
- **T-2B.3** Recipient read of a public file: an enrolled non-owner downloads using `get_wrapped_keys`
  through the unified path; a non-enrolled authenticated user gets ciphertext but `wrapped_keys=null`
  and fails closed.
- **T-2B.4** `republish` admits a newly-enrolled user (T-N4): enroll a user after publish, republish,
  assert the new user now has a row and can decrypt.
- **T-2B.5** Integration smoke (extend `tests/test_api_smoke.py`): upload→enroll(second user)→
  publish→second user downloads and decrypts end-to-end.

### Cross-cutting
- **T-X.1** Update `README.txt` PART I §6/§9/§11 to reflect new commands, endpoints, the removed
  cache, schema v6, and PROTOCOL_VERSION 2. (Docs only; PART I is the source of truth for reality.)
- **T-X.2** `client/sharing.py` decision: it is currently dead (only thin wrappers over the keystore,
  `client/sharing.py:11-63`, not imported by `cli.py` which calls `ks.wrap_file_keys` directly). The
  unified `acquire_file_keys` + `verify_x25519_self_sig` helpers should live in a **revived
  `client/sharing.py`** (it is the natural home for "key wrapping/unwrapping/verification glue"),
  replacing its current pass-through functions. This revives the module rather than adding a new one.
  (Refactor; behavior covered by 2A/2B tests.)

---

## 11. Open questions for the owner

1. **v1 compatibility read (§6.6).** Ship the §6.6(A) version-branch so a v2 client can still **read**
   existing v1 files, or do a **hard cutover** (all old files must be re-uploaded)? Default
   recommendation: ship (A) for a smooth transition; it leaves v1 files at the weaker (no-root)
   metadata binding until re-uploaded.
2. **"Public" definition (§4.4).** Confirm that "published to the current enrolled population (with
   re-publish to admit later enrollees)" is the intended semantics, vs. an expectation that any future
   enrollee automatically gains access (which would require the rejected new-primitive scheme).
3. **Enrolled-set leakage (§4.8, L5).** Accept that the server learns the *set* of recipients of each
   public file at publish time as the price of avoiding a new key-commitment primitive? If
   unacceptable, a committing-AEAD single-bundle design is a separate security-reviewed item.
4. **`MAX_PUBLISH_FANOUT` value (§7).** Is 1024 the right cap, or should publish to a very large
   directory be an operator-mediated action?
5. **X25519 enrollment authority (§5.4).** Self-service enrollment over the tunnel (recommended,
   gated on the operator having already set Ed25519), or operator-only enrollment to mirror
   `register-pubkey`? Self-service is safe because the self-sig is verifiable, but it does let any
   authenticated user populate their own X25519 row.
6. **Public→private downgrade.** Out of scope here (would orphan reader bundles). Needed now, or
   deferred to a key-rotation/version-history item?
7. **Directory `enrolled` visibility.** Listing all usernames+public keys to any authenticated user
   is inherent to a directory; confirm this disclosure is acceptable (it is the same class as
   public-file owner disclosure today).

---

## 12. Cross-reference index (where each item touches code)

- 2A: `client/cli.py:266-284` (cache write, remove), `347-378` (download fork, unify),
  `517-530` (share cache read, replace); `server/database.py:633-701` (reuse share row +
  get_wrapped_keys); new `self_keys` handler alongside `server/storage.py:983-1107`.
- 2B: `server/policy.py:37-38` (public access policy, unchanged); `server/storage.py:983-1107`
  (`/share` reuse), `549-554`/`674-683` (visibility set at finalize — add `/visibility` endpoint);
  `wrapping.rs` reused unchanged.
- 2C: `server/database.py:36-53` (users schema), `19`/`148-164`/`286-291` (version + migration);
  `server/auth.py:103-125` (canonicalization to share); `server/admin.py:100-133` (Ed25519
  register-pubkey, the chain root); `rust/keycore/src/lib.rs:85-89`/`163-175` (sign/verify reused).
- 2D: `shared/models.py:21` (version), `83`/`375-378` (sentinel + invariant — keep),
  `339-340` (validate), `394-417` (ChunkAAD — leave), new `build_metadata_aad`;
  `client/encryptor.py:150-177` (order — keep), `211-216` (encrypt AAD), `349`/`469-506` (decrypt).
