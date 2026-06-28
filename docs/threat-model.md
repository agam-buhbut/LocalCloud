# LocalCloud — Threat Model

The design rule (README.txt PART II §10): **the server is a hostile storage
box.** All confidentiality, metadata privacy, and forward secrecy live on the
client. This document states what that buys and what it does not.

## Assets

- **File contents** — must never be readable by the server or anyone with the
  disk. Protected by per-file XChaCha20-Poly1305 with client-held keys.
- **File/sharing metadata** (beyond filenames) — in the E2E-encrypted metadata
  blob; the server sees only the ciphertext.
- **Long-term identity keys** (X25519 enc + Ed25519 sign) — client-side,
  encrypted at rest (Argon2id keystore), `mlock`ed in memory.
- **Session HMAC secret** — server-side; forges any token if leaked.

## What the server legitimately sees (plaintext on the server)

`file_id`, **filename**, owner, visibility mode, sharing list, timestamps,
padded size, blob identifiers, and versioning/integrity data (Merkle root,
signatures). Everything else is in the encrypted metadata blob. Filenames are
plaintext by design — clients that need filename privacy must encode that into
the (encrypted) metadata and use opaque filenames.

## Adversaries & outcomes

| Adversary | Outcome | Mechanism |
|---|---|---|
| Random internet scanner | sees nothing | only the WG UDP port is open, and only while online; default-deny nftables |
| Brute-force login | bounded per peer | server-side Argon2id + the authoritative composite (peer, username) in-memory limiter + a per-(peer, username) and a per-peer-IP DB gate + WG-key prerequisite. Rate limits are **peer-scoped** (AUTH-1): one WireGuard peer can no longer lock another peer out of an account (cross-peer lockout DoS), but consequently a brute-force ceiling against a single account scales with the number of *provisioned* WG peers (N peers ⇒ up to N × max_attempts), each peer itself Argon2id- and rate-limit-bounded. Acceptable under the single-tunnel WG model where peers are explicitly enrolled. |
| **Server compromise (reads data at rest)** | **cannot read contents or non-filename metadata** | E2EE terminates on the client; the server never holds file/meta keys in plaintext (owner keys are wrapped to the owner's own X25519) |
| Disk theft (powered off) | nothing | LUKS2 + encrypted LVM, console-only unlock, no keyfile/TPM auto-unlock |
| Metadata inspection at rest | only the plaintext fields above | the rest is ciphertext |
| Replay / rollback | in-version replay rejected; whole-file rollback NOT detected | transport replay protection + the signed Merkle root pins each chunk/geometry to ONE file version; a hostile server CAN still serve an older, still-validly-signed version (no monotonic anchor) — see "Out of scope" |
| Retroactive decryption after key compromise | wrapped keys still required | per-file random keys, per-recipient ephemeral-static X25519 wrapping (forward secrecy); no shared global keys; no server-side caching of wrapped keys |
| Username enumeration | suppressed | timing-equalized auth/share/unshare + fixed-shape, constant-deadline pubkey directory |
| Peer impersonation inside the tunnel | prevented | identity derived from the WireGuard source IP with /32-per-peer AllowedIPs (WireGuard cryptokey routing drops spoofed source IPs); no reverse proxy / forwarded headers. RATIFIED model (owner decision 2026-06-22): `request.remote_addr` IS the peer identity, sound ONLY under single-tunnel WireGuard — `config.validate()` fails closed on a public/unspecified bind, and the acceptance script verifies external reachability + /32-per-peer. Binding the session token to the WG peer *pubkey* (a map keyed by source IP) was evaluated and deferred: WG /32 already stops live IP-takeover, so it would only add churn/misconfig detection at the cost of a new root-trust file. See plans/2026-06-22-f8-peer-binding-design.md. |

## Out of scope / weak against (stated honestly)

- **Whole-file rollback / version-replay** — a hostile server can serve an
  older, still-validly-signed version of a file and the client cannot detect
  it. There is no signed monotonic version anchor or client-side high-water
  mark (`MetadataBlob.version_number` is a reserved placeholder, never
  compared). Per-version integrity/authenticity IS enforced (signed Merkle
  root verified before decrypt); only cross-version freshness is unprotected.
- **Recipient key exchange on FIRST contact is TOFU** — the directory-based
  `share` path resolves the recipient's X25519 key from the (hostile) server
  and verifies the recipient's Ed25519 self-signature over it. That self-sig
  proves only that the `{ed25519, x25519, self_sig}` triple is internally
  consistent; it is necessary but NOT sufficient, because the server supplies
  the Ed25519 too and could, on first contact, mint a self-consistent triple it
  controls (and then unwrap the shared file). The trust anchor is therefore
  Trust-On-First-Use on the recipient's Ed25519: the first SUCCESSFUL directory
  share pins it (client-side, `<key-file>.recipient_pins.json`), and any later
  server substitution of that recipient's identity key is refused fail-closed —
  mirroring the owner-pubkey TOFU pin on the download path. For authenticated
  first contact, `share --recipient-pubkey <hex>` supplies an out-of-band
  X25519 anchor and bypasses the directory and the pin entirely. So "server
  compromise cannot read shared-file contents" holds only once a recipient has
  been pinned via an authentic first contact (or via `--recipient-pubkey`).
- **Total hardware loss** — no off-box replica beyond the (offline, encrypted)
  backup HDD; losing both disks loses the data.
- **Client-side compromise** — if the client device is owned, plaintext and
  unlocked keys are exposed; LocalCloud cannot defend the client's own RAM.
- **Live coercion while online** — an operator forced to unlock and serve.
- **Traffic-analysis of volume/timing** at the network edge (sizes are padded;
  fine-grained timing/volume correlation is not fully obscured).
- **Server-side secret zeroization** — the session HMAC secret and passwords
  live in Python `str` (immutable, best-effort zeroization). Mitigated by
  `LimitCORE=0` + `MemorySwapMax=0` + short token lifetime + LUKS at rest
  (see `deploy/README.md`), not by in-memory scrubbing.

## Cryptographic discipline (enforced in code/tests)

Per-file random keys; never reuse keys; nonce uniqueness and key isolation
covered by property-based tests; all serialized structures explicitly
versioned; hardened CBOR decoder; fail-closed decryption (atomic, Merkle-
verified); randomness aborts if the OS entropy source fails; no custom
primitives — only audited libraries (PyNaCl, RustCrypto).
