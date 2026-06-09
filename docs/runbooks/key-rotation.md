# Runbook: Key rotation

Two independent rotations. Tested guarantees are pinned by
`tests/test_key_rotation.py` (session secret) and the keystore/share tests
(identity keys).

## 1. Session HMAC secret (server-side)

**Effect:** invalidates **every outstanding session token immediately.** A
token is `base64(payload).HMAC(secret, payload)`; once the server verifies
against a new secret, all old signatures fail (`SessionExpiredError`). This is
proven in `tests/test_key_rotation.py`
(`test_rotated_secret_invalidates_outstanding_token`).

**When:** suspected secret exposure (core dump, swap leak, operator error), or
on a routine schedule.

**Procedure (console):**
```sh
umask 077
python3 -c 'import os;print(os.urandom(48).hex())' > /etc/localcloud/session.secret.new
chmod 600 /etc/localcloud/session.secret.new
mv /etc/localcloud/session.secret.new /etc/localcloud/session.secret
systemctl restart localcloud.service     # reloads the secret via LoadCredential
```
All users must log in again. The kill-switch (`--rotate-secret`) does this as
part of an emergency takedown.

**Interaction with `session_version`:** the two revocation mechanisms are
independent and complementary. Secret rotation kills **all** tokens for **all**
users at once (coarse, instant). `session_version` (bumped per-user via
`python -m server.admin bump-session <user>` or `disable-user`) revokes one
user's tokens without disturbing others (fine-grained). Use `bump-session` for
a single compromised account; rotate the secret for a server-secret incident.

## 2. User identity keys (X25519 / Ed25519, client-side)

**Effect on existing shares:** shares are wrapped to the recipient's *old*
X25519 key. After a recipient rotates identity keys, **old shares can no longer
be unwrapped by the new key and must be re-established** by each file's owner
re-wrapping to the new key. There is no server-side re-wrap (the server never
holds plaintext keys).

**Procedure:**
1. The rotating user generates a new identity (`localcloud init` to a new key
   file) and re-enrolls the new X25519 (self-signed by the new Ed25519) via the
   directory; the operator re-pins the new Ed25519 fingerprint out-of-band and
   `register-pubkey`s it.
2. The user migrates their own wrapped file keys to the new identity with
   `localcloud migrate-keys` (fail-closed: it does not delete the old wrapping
   until the new self-wrap is confirmed).
3. **Each owner who shared with this user re-runs** `localcloud share <file>
   <user>` so the file keys are re-wrapped to the new X25519. Until then those
   shares are dead for the recipient (fail-closed — no silent plaintext
   fallback).
4. Revoke the old WireGuard key if the device itself is being retired
   (`deploy/wireguard/` — delete the `[Peer]` block and `wg syncconf`).
