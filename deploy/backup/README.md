# LocalCloud — Encrypted backups (Phase 6 / PART II §7)

Internal-HDD, **offline-by-default**, LUKS2-encrypted backups holding only
server-side **ciphertext + the encrypted-metadata db** — never any plaintext
file contents (the server never has them).

## What gets copied

| Copied | Not copied | Why |
|---|---|---|
| `/srv/cloud/meta.db` (consistent snapshot) | `/srv/cloud/staging/` | staging is transient, possibly-inconsistent in-flight uploads |
| `/srv/cloud/blobs/**` (immutable ciphertext) | any client plaintext | there is none on the server |

`meta.db` contains plaintext **filenames + sharing/visibility/size metadata**
(the same plaintext the running server already holds — see the threat model);
everything else in it is opaque. The backup disk is LUKS2, so all of it is
encrypted at rest. No file *contents* are ever written in the clear.

## Scripts

- **`localcloud-backup-copy.sh SRC DEST`** / **`localcloud-restore-copy.sh SRC DEST`**
  — the data-copy core, no LUKS. Tested by `tests/test_backup_restore.py`
  (consistent live-WAL snapshot, blob byte-integrity, staging exclusion,
  restore round-trip). `meta.db` is snapshotted via sqlite's online backup API
  so a copy taken while the daemon is running is transactionally consistent —
  a plain `cp` of a WAL db can be torn.
- **`localcloud-backup.sh`** / **`localcloud-restore.sh`** — operator wrappers
  that unlock + mount the offline LUKS2 HDD, call the copy core, then unmount
  and **re-lock** the disk (offline-by-default). UNTESTED in CI — they need the
  real LUKS device; run them from the physical console.

> On the real box, for large/incremental backups swap the `cp -a` blob line in
> the copy scripts for `rsync -a --delete`. The blob tree is immutable, so
> rsync is safe and far cheaper.

## Backup (operator, at the console)

```sh
deploy/backup/localcloud-backup.sh        # prompts for the disk passphrase
# -> unlocks lc-backup, snapshots meta.db + blobs/, unmounts, re-locks
```

## Restore drill (the Phase 6 acceptance — do this BEFORE trusting backups)

A backup→wipe→restore drill must reproduce a working server:

```sh
# 1. take a backup
deploy/backup/localcloud-backup.sh

# 2. simulate loss
systemctl stop localcloud.service
mv /srv/cloud /srv/cloud.lost      # or wipe on a throwaway box

# 3. restore
install -d -o localcloud -g localcloud -m 0700 /srv/cloud
deploy/backup/localcloud-restore.sh    # stops daemon, restores, chowns

# 4. verify the server comes back
systemctl start localcloud.service
#    log in as a user and download a pre-existing file — it must decrypt.
```

## Plaintext spot-check (acceptance)

Confirm the backup media contains no plaintext file contents:

```sh
# Mounted backup at /mnt/lc-backup. Blobs must look like high-entropy
# ciphertext (no readable strings from your files):
strings -n 8 /mnt/lc-backup/localcloud/blobs/* | head
#   -> should be noise. meta.db will show filenames (expected, by design);
#      it must NOT show any file *content*.
```
