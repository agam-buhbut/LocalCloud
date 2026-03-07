Goal
Lenovo V14 IIL running barebones Debian 13 + encrypted LVM, hosting a globally reachable personal cloud storage server that is:
hardened and minimal (low attack surface)
reachable only through WireGuard
supports full E2EE storage (server cannot read file contents or metadata except filenames)
supports public / shared / private file visibility rules
can be taken offline on a schedule or instantly by operator
physical-console-only administration
local encrypted backups to internal HDD

Machine (server laptop)
Features
Minimal Debian 13
No GUI No bluetooth / audio / camera / mic stacks Only essential packages: kernel, networking, storage, WireGuard, service deps
No sleep or suspend states enabled; system remains fully awake when online and fully offline otherwise
Encrypted storage
Primary disk (SSD): LUKS2 + encrypted LVM containing OS and live cloud data
Secondary disk (HDD): internal 750gb WD Blue HDD, separate LUKS2 partition used only for encrypted backups, never auto-mounted
Server boot requires local unlock (physical presence)
Physical-console-only admin No admin SSH No remote root access
Strict service model
Separate unprivileged users for tunnel and cloud service
Cloud service has no plaintext access to user data or metadata
Backup disk only mountable by operator from console
Hardening requirements
Network exposure Only one inbound UDP port open (WireGuard) Everything else closed
Mandatory Access Control
AppArmor enforced
systemd sandboxing
No new privileges, no device access, no raw sockets
Filesystem writes restricted to explicit directories
Root filesystem mounted read-only with writable paths via tmpfs or bind mounts
Logging
Minimal security logs only (connections, auth failures, quota events, backup events) No plaintext metadata

Firewall + Availability Control Layer
Features
Default deny inbound via nftables
Only allow WireGuard UDP port
Scheduled uptime
systemd timers add/remove firewall rule controlling WireGuard availability
Offline means no listening port and no established sessions
Operator kill-switch
Single command that removes firewall rule, kills active sessions, and stops services
Rate limiting
nftables rate limiting on WireGuard port prior to daemon
No tunnel-level rate limiting relied upon

Tunnel (WireGuard transport layer)
Goal Provide secure, authenticated, replay-resistant transport with minimal metadata leakage
Transport
WireGuard using Curve25519 and ChaCha20-Poly1305
Built-in replay protection and forward secrecy
Server public key pinned client-side
Client authentication via WireGuard public key allowlist
Application authentication inside tunnel using username + password
Design rule
Tunnel is transport-only
No file keys, no metadata keys, no persistence of secrets
Compromise of tunnel does not compromise stored data

Server Application (cloud logic)
Cloud server runs only behind WireGuard
4.1 Core responsibilities
User management
Accounts: username
Auth factors: WireGuard key + username + password
Quota enforcement per user enforced server-side
File storage
Store encrypted blobs and encrypted metadata blobs
Server cannot read contents or metadata except filenames
Sharing rules
File visibility modes: private, shared to specific users, public to authenticated users
Server enforces access policy only

4.2 Data model
Plaintext on server
file_id
filename
Encrypted metadata blob (E2EE)
owner username
visibility mode
sharing list
timestamps
file size padded to fixed block sizes
blob identifiers
versioning and integrity data

E2EE Design with Forward Secrecy
Goal
Server stores files and metadata but cannot decrypt them
Sharing must work without leaking metadata
Past data remains secure after compromise
5.1 Identity keys
Each user has long-term encryption key pair and long-term signing key pair
Separate from WireGuard keys
Stored encrypted on client
5.2 File and metadata encryption
Per file generate random file_key and meta_key
Encrypt file contents with file_key using XChaCha20-Poly1305
Encrypt metadata blob with meta_key using XChaCha20-Poly1305
Pad ciphertext and metadata to fixed-size blocks to reduce size leakage
Keys are never reused
5.3 Forward secrecy
Per-file random keys
Per-recipient key wrapping
No shared global keys
Public access requires on-demand key wrapping per user
No server-side caching of wrapped keys
Compromise of long-term keys does not allow retroactive decryption without wrapped keys
5.4 Access control
Private: keys encrypted only to owner
Shared: keys encrypted individually to each recipient public key
Public: server only authorizes request, client generates wrapped keys on demand

Client Application
Features
Local key management
Local encryption and decryption
Upload and download logic
Keys encrypted at rest and unlocked only in memory
Keys locked on inactivity
Plaintext files exist only in memory or tmpfs
Upload
Encrypt locally then upload ciphertext in chunks with integrity verification
Download
Fetch ciphertext then decrypt locally with integrity verification
Sharing
Client handles all key wrapping and signing
Quota display
Server reports usage only
Secure deletion
Rely on encryption and key destruction, not physical shredding

Backup System
Internal HDD backup only
Encrypted with LUKS2
Offline by default
Mounted manually by operator only
Stores only encrypted blobs and encrypted metadata
No plaintext ever written
Backup flow
Operator mounts disk
Snapshots or rsync encrypted data
Operator unmounts disk

Operator Controls
Create and disable users
Set quotas
Revoke WireGuard keys
Force server offline instantly
Mount and unmount backup disk
Rotate keys and credentials

Security check
Strong against random scanning, brute force, server compromise reading data, disk theft, metadata inspection, replay, and retroactive decryption
Weak against total hardware loss, client-side compromise, and live coercion while online

Implementation Instructions
Server
Minimal Debian with encrypted LVM
WireGuard only
systemd services for cloud daemon
AppArmor profiles
Filesystem layout
/srv/cloud/blobs/
/srv/cloud/meta.enc
Client
systemd services for cloud daemon
AppArmor profiles
Stores encrypted private keys and pinned server identity
Implements encrypt upload verify and download verify decrypt
Design rule
The server is a hostile storage box and all confidentiality, metadata privacy, and forward secrecy live on the client

Program instructions:
The client encryption program, upload/download API, Argon2 authentication layer, and per-user quota logic together form a distributed trust boundary where confidentiality and integrity terminate exclusively at the client, and the server enforces policy without access to plaintext or unwrapped symmetric keys. The system must be designed assuming a malicious storage server with full read/write access to stored ciphertext and metadata blobs, the ability to replay old state, reorder chunks, truncate uploads, and snapshot disks. The client must therefore provide cryptographic isolation at file granularity, strong misuse resistance, replay detection, authenticated chunking, strict key lifecycle discipline, and deterministic failure behavior.

The client encryption subsystem must implement per-file cryptographic isolation. For every file, it must generate independent, uniformly random 256-bit file_key and meta_key values using a CSPRNG backed by the OS entropy source. Keys must never be derived from filenames, timestamps, counters, or user secrets. Nonces must be 192-bit random values for XChaCha20-Poly1305 and must never be reused with the same key. Each encrypted chunk must use a unique nonce, and the tuple (file_key, nonce) must be globally unique within the lifetime of the file. The encryption process must treat file contents as a stream, chunked at a fixed size boundary such as 4 MiB, padded to a multiple of that size to reduce length leakage. Each chunk must be encrypted independently with AEAD, with associated data binding file_id, chunk_index, protocol_version, and optionally total_chunks to prevent cross-file substitution and chunk reordering. The metadata blob must be serialized deterministically (e.g., canonical CBOR or length-delimited binary struct), padded to a fixed size class (e.g., 1 KiB, 4 KiB, or power-of-two bucket), and encrypted separately under meta_key. No plaintext metadata except filename may ever be transmitted or persisted server-side.

The file format must be rigidly versioned and self-describing. A header should contain a magic constant, protocol version, file_id (128-bit random), chunk_size, total_chunks, and possibly a Merkle root hash. The header itself must be authenticated either by signing or by embedding it in associated data of the first chunk. If Merkle trees are used, each chunk hash must be computed over ciphertext and organized into a binary tree whose root is signed using the client’s Ed25519 signing key to prevent server rollback attacks. The client must verify all AEAD tags and Merkle proofs before releasing any plaintext to callers. Partial decryption is forbidden; decryption must fail atomically.

Identity management must use separate long-term keypairs for encryption (X25519) and signing (Ed25519). These keys must be generated client-side and stored only in encrypted form. Key storage must use Argon2id with high memory cost parameters (e.g., >=512 MiB memory, t >=3, p=1 unless parallelism justified) to derive a master encryption key from a user password and a per-user random salt. The encrypted key bundle format must include versioning, salt, Argon2 parameters, and an AEAD-protected payload containing serialized private keys. The password verification process must be constant-time and must not reveal whether decryption failed due to wrong password or corrupted ciphertext. The client must lock private key memory using mlock or equivalent, disable core dumps, zeroize buffers after use, and avoid unintended copies by using explicit zeroizing types. Key material must never be logged, formatted, or included in panic traces.

Sharing requires per-recipient key wrapping. For each recipient public key, the client must compute an X25519 shared secret, derive a wrapping key using HKDF or BLAKE2-based KDF with domain separation including file_id and context label, and encrypt file_key and meta_key under this wrapping key with AEAD. Wrapped keys must be stored alongside encrypted metadata but never in plaintext. There must be no group symmetric keys and no reuse of wrapping keys across files. Public visibility must not imply universal decryption keys; instead, on-demand wrapping per authenticated user must occur client-side. The server must not persist long-lived wrapped keys for unauthenticated public access unless policy explicitly allows and leakage implications are accepted.
The upload API must accept only authenticated requests over WireGuard transport and bind to the tunnel interface exclusively. Application-layer authentication must require username plus password verified via Argon2id hashes stored server-side. Server-side password storage must use Argon2id with high memory cost (lower than client but still GPU-resistant, e.g., >=128 MiB). Stored password records must include per-user random salts and full parameter sets. Password comparison must use constant-time equality checks. Login endpoints must implement rate limiting independent of WireGuard to prevent brute force attempts from authenticated peers. Upon successful authentication, the server must issue a short-lived session token signed with a server-side secret key and bound to user_id, peer public key, and expiration time. Session tokens must be opaque and verified on every request.

The upload protocol must be chunk-aware and integrity-enforcing. The client must upload encrypted chunks with explicit file_id and chunk_index. The server must write chunks to a staging area and compute BLAKE2b hashes of received ciphertext. After full upload, the client must send a finalize request including total_chunks and expected file hash. The server must verify chunk count and optionally recompute aggregate hash before committing metadata. Incomplete uploads must expire and be garbage-collected. The server must never accept plaintext; content-type enforcement should reject unexpected formats.

The download API must return ciphertext only. The server must not transform or re-encrypt data. The client must verify file_id consistency, total_chunks, AEAD tags, and optional Merkle proofs before decrypting. If any chunk fails authentication, the entire download must abort. The server may support range requests, but the client must treat each chunk as independently authenticated and must not release partial plaintext without verifying integrity of the relevant authenticated unit.

Per-user quota logic must operate exclusively on ciphertext size, not plaintext size. The server must track total allocated bytes per user as sum of stored ciphertext chunks and encrypted metadata blobs. Quota checks must occur before finalization of uploads. Quota accounting must be atomic; concurrent uploads must not allow race conditions that exceed limits. This requires transactional updates or database-level compare-and-swap semantics. Deletion must immediately decrement usage accounting. Garbage collection of abandoned uploads must also reconcile quota state. The server must never infer plaintext size beyond padded ciphertext length and must not store unpadded length.

All APIs must fail closed. Any decryption error, authentication failure, malformed request, or state mismatch must terminate the operation without partial success. Error messages must be generic and not leak whether a username exists, whether a password was correct, or whether a file_id is valid. Logging must exclude filenames, plaintext sizes, wrapped keys, or metadata contents. Only high-level events such as authentication success/failure, quota exceedance, upload completion, and download attempts may be logged.

The entire system must enforce strict versioning and protocol negotiation. Each serialized structure must include explicit version fields to allow migration. All parsers must be fuzz-tested against malformed input. All cryptographic operations must be covered by property-based tests verifying nonce uniqueness, key isolation, and failure on corruption. Any unsafe code must be minimized and audited. Randomness acquisition must abort if the OS entropy source fails. The client must not implement custom cryptographic primitives; it must rely on well-audited libraries and treat misuse resistance as a primary design constraint.
In summary, the client enforces confidentiality, forward secrecy at file granularity, and integrity against replay and reordering; the upload/download API enforces authenticated, atomic, integrity-checked ciphertext transport; Argon2 authentication enforces memory-hard password verification with constant-time behavior; and quota logic enforces storage limits strictly over ciphertext accounting without metadata leakage. Every boundary must assume adversarial conditions, deterministic failure, and zero tolerance for cryptographic misuse.
