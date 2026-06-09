# Runbook: Operations

Physical-console-only administration. There is **no** remote admin path: no
admin SSH, no HTTP account endpoints. Everything below is run by the operator
at the machine. Deployment artifacts referenced here live under `deploy/`.

## Emergency takedown (kill-switch)

Take the box offline instantly (README.txt PART II §2):
```sh
deploy/scripts/localcloud-killswitch.sh              # close port, sever sessions, stop services
deploy/scripts/localcloud-killswitch.sh --rotate-secret   # also invalidate all tokens
```
Bring it back:
```sh
systemctl start wg-quick@wg0.service localcloud.service
/usr/local/sbin/localcloud-online.sh
```

## Scheduled uptime (online/offline)

Availability is an nftables rule toggled by the `localcloud-online` /
`localcloud-offline` units (and their timers). Offline = the WG port is closed;
no listening port, new handshakes refused. Manual:
```sh
/usr/local/sbin/localcloud-online.sh     # open
/usr/local/sbin/localcloud-offline.sh    # close (existing sessions drain)
```
Edit the `*.timer` `OnCalendar=` for your window; enable with `systemctl enable --now`.

## User lifecycle (admin CLI — PART I §5)

```sh
python -m server.admin create-user alice            # prompts for password
python -m server.admin set-quota alice 5368709120    # 5 GiB
python -m server.admin register-pubkey alice <ed25519-hex>   # pin identity (out-of-band)
python -m server.admin disable-user alice            # also bumps session_version (revokes tokens)
python -m server.admin bump-session alice            # revoke alice's live tokens only
python -m server.admin list-users
python -m server.admin run-cleanup                   # one-shot staging GC
```
The user gets their Ed25519 hex from `localcloud init` and hands it to the
operator out-of-band; the operator pins it with `register-pubkey`.

## WireGuard peer add / revoke

Add: generate the client keypair, add a `[Peer]` with a **/32** `AllowedIPs`
to `/etc/wireguard/wg0.conf`, then `wg syncconf wg0 <(wg-quick strip wg0)`.
Revoke: delete the `[Peer]` block and `wg syncconf` again (see
`deploy/wireguard/wg0.conf.example`). A revoked key can no longer complete a
handshake, and its source IP no longer maps to an identity.

## Backup & restore

See `deploy/backup/README.md`. Summary:
```sh
deploy/backup/localcloud-backup.sh     # mount offline HDD, snapshot, re-lock
deploy/backup/localcloud-restore.sh    # stop daemon, restore, chown, (then start)
```
Run the **backup→wipe→restore drill** at least once before trusting backups
(Phase 6 acceptance). The data-copy core is tested by
`tests/test_backup_restore.py`.

## Incident response (suspected compromise)

1. **Contain:** `localcloud-killswitch.sh --rotate-secret` (offline + sever
   sessions + invalidate all tokens).
2. **Triage:** read journald security events (connections, auth failures, quota
   events). No plaintext metadata is logged.
3. **Rotate:** if the server secret may have leaked, the kill-switch already
   rotated it. If a specific account is implicated, `disable-user` (revokes its
   tokens) and `register-pubkey` a fresh identity after the user re-keys
   (see `key-rotation.md`).
4. **Verify integrity:** clients fail-closed on download (Merkle + signature),
   so a tampered blob cannot decrypt; spot-check a known file restores.
5. **Recover:** restore from the offline backup if data was altered; bring the
   box back online only after the cause is understood.
