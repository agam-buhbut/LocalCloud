# Disk encryption layout (README.txt PART II §1)

> **Manual, console-only procedure.** Disk encryption is set up at install time
> with physical presence; it is not scripted here because a wrong `cryptsetup`
> command destroys data. This documents the intended layout and the commands to
> achieve it — run them deliberately, with the right device names for YOUR box.

## Layout

- **Primary disk (SSD)** — `LUKS2 + encrypted LVM` holding the OS and the live
  data dir `/srv/cloud`. Unlocked at boot by a passphrase entered at the
  **physical console** (no remote unlock, no keyfile on disk).
- **Secondary disk (HDD)** — a **separate** `LUKS2` partition used *only* for
  encrypted backups. **Never auto-mounted** (no `/etc/fstab` entry, or
  `noauto`). The operator mounts it from the console only during a backup
  (see `deploy/backup/`).

## Primary SSD (do this in the Debian installer, "Encrypted LVM" option)

The Debian installer's *guided — use entire disk and set up encrypted LVM*
produces exactly this: a LUKS2 container with an LVM VG inside (root + swap).
Put `/srv/cloud` on the encrypted VG (a dedicated LV is cleanest):

```sh
# inside the encrypted VG, e.g. vg0:
lvcreate -L 200G -n cloud vg0
mkfs.ext4 -m 0 /dev/vg0/cloud
echo '/dev/vg0/cloud /srv/cloud ext4 defaults,noatime 0 2' >> /etc/fstab
mount /srv/cloud
```

Disable swap, or ensure swap is on the encrypted VG (the installer's encrypted
LVM keeps swap inside LUKS — verify with `lsblk`). The daemon also sets
`MemorySwapMax=0`, but a plaintext swap partition would defeat that.

## Secondary backup HDD (offline by default)

```sh
# ONE TIME — destroys the target partition:
cryptsetup luksFormat --type luks2 /dev/sdb1
# Backups are mounted manually only; do NOT add to fstab (or use noauto):
#   cryptsetup open /dev/sdb1 backup
#   mount /dev/mapper/backup /mnt/backup
#   ... rsync encrypted blobs ...  (deploy/backup/)
#   umount /mnt/backup && cryptsetup close backup
```

## Boot

- Boot requires the LUKS passphrase at the console (physical presence).
- No `crypttab` keyfile, no TPM auto-unlock — disk theft must not yield data
  (PART II §9: "strong against disk theft").
