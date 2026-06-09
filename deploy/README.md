# LocalCloud — Deployment & Hardening (Phase 5)

> **Status: UNVALIDATED IN CI.** Everything in `deploy/` provisions an
> operating system, a kernel WireGuard interface, an nftables ruleset, systemd
> units, and an AppArmor profile. **None of it can run or be tested in the
> application repo's sandbox** — it must be applied and verified on the real
> Debian box. Treat every file here as a reviewed-but-untested template:
> read it, adapt the placeholders, and run the acceptance checks at the bottom
> before trusting it.

This directory is the "hostile box" deployment described in `README.txt`
PART II §1–3, 8. The application layer (client/server/shared/keycore) is built
and tested in the repo root; this tree is the OS/network/service hardening that
wraps it.

## Consistency contract (every file here uses these — change in ONE place)

| Thing | Value | Why |
|---|---|---|
| OS | minimal Debian (stable), no GUI | low attack surface (PART II §1) |
| Cloud service user | `localcloud` (unprivileged, no shell, no login) | the daemon must never run as root (SEC) |
| Data root | `/srv/cloud` | matches `server.config` default `data_dir` |
| Blobs / staging / db | `/srv/cloud/blobs`, `/srv/cloud/staging`, `/srv/cloud/meta.db` | matches `config.py` derived defaults |
| Session secret | `/etc/localcloud/session.secret` (root:root 0600) | injected via systemd `LoadCredential=` (never an env var) |
| WireGuard interface | `wg0`, server addr `10.0.0.1/24`, listen `51820/udp` | the only inbound port |
| App bind | `10.0.0.1:8443` (the WG interface address) | `LOCALCLOUD_BIND_HOST`; the app refuses public binds |
| Hypercorn workers | **1** (single process) | MANDATORY — see "Single-worker requirement" |

If you change any value, grep `deploy/` for the old one — the units, ruleset,
AppArmor profile, and scripts all reference these.

## Single-worker requirement (SEC-M3) — do not skip

Two server invariants hold **only under a single worker process**:

1. **Login rate limiting** (`server/auth.py`) is in-process state. With N
   workers each worker keeps its own counter, so the effective limit is N×.
2. **Argon2 concurrency cap** (`argon2_max_concurrent`, Phase 4F) is
   per-process; under N workers the real memory ceiling is N× (OOM risk).

`deploy/systemd/localcloud.service` therefore launches Hypercorn with
`--workers 1`. If you ever need multiple workers, the rate limiter and the
Argon2 cap must first move to shared (DB/Redis) state — that is a code change,
not a config change.

## Peer identity (SEC-M2)

The app derives the client identity from the **WireGuard source IP**
(`server/auth.py` binds tokens to it). For that to be trustworthy:

- The app binds **only** to `wg0` (`10.0.0.1`) — never `0.0.0.0`. Enforced by
  `LOCALCLOUD_BIND_HOST` + the app's own public-bind refusal.
- **No reverse proxy and no forwarded-header middleware** in front of the app.
  Do not put nginx/Caddy/Traefik in the path — a forwarded `X-Forwarded-For`
  would let a peer spoof another peer's identity. Hypercorn binds the WG
  address directly.
- Ideally pin WireGuard `AllowedIPs` to a /32 per peer so the source IP ↔ WG
  pubkey mapping is 1:1 (see `deploy/wireguard/wg0.conf.example`).

## Server-side secret hygiene (SEC-M2/secret)

Unlike the Rust client, the server keeps the session HMAC secret and passwords
in plain Python `str` for the process lifetime, and Python `str` immutability
makes true zeroization best-effort. The real controls are process-level and
live in `localcloud.service`:

- `LimitCORE=0` — no core dump can spill the secret to disk.
- `MemorySwapMax=0` — the cgroup cannot swap the secret out.
- `LoadCredential=session_secret:/etc/localcloud/session.secret` — the secret
  is passed via the credentials directory, never an environment variable
  (env is world-readable via `/proc/<pid>/environ` to the same uid).
- Short `LOCALCLOUD_SESSION_LIFETIME` keeps the forgery window small if the
  secret ever leaks.

## Install order (on the box, as root, from the physical console)

1. **OS hardening:** `deploy/os/harden-debian.sh` (minimal packages, no
   sleep/suspend, strip bluetooth/audio/camera/mic, sysctl). Review first.
2. **Disks:** provision LUKS2 + encrypted LVM per `deploy/os/DISKS.md`
   (primary SSD = OS + `/srv/cloud`; secondary HDD = offline backups).
3. **App user + dirs:**
   ```sh
   useradd --system --home-dir /srv/cloud --shell /usr/sbin/nologin localcloud
   install -d -o localcloud -g localcloud -m 0700 /srv/cloud /srv/cloud/blobs /srv/cloud/staging
   install -d -o root -g root -m 0700 /etc/localcloud
   python3 -c 'import os;print(os.urandom(48).hex())' > /etc/localcloud/session.secret
   chmod 600 /etc/localcloud/session.secret
   ```
4. **Install the app** into a venv the `localcloud` user can execute
   (e.g. `/opt/localcloud/venv`); build `keycore` is client-side only and not
   needed on the server.
5. **WireGuard:** `deploy/wireguard/` (generate server + peer keys, fill the
   allowlist, `systemctl enable --now wg-quick@wg0`).
6. **Firewall:** `nft -f deploy/nftables/localcloud.nft`; make it boot-persistent
   (`systemctl enable nftables`, ruleset in `/etc/nftables.conf`).
7. **AppArmor:** install `deploy/apparmor/usr.local.bin.localcloud-server`,
   `apparmor_parser -r`, confirm `aa-status` shows it enforcing.
8. **Logging:** `deploy/logging/journald-localcloud.conf` → `/etc/systemd/journald.conf.d/`.
9. **Service + timers:** copy `deploy/systemd/*` to `/etc/systemd/system/`,
   `systemctl daemon-reload`, `systemctl enable --now localcloud.service`,
   and enable the uptime timers if you want scheduled availability.

## Acceptance checks (run on the box — these are the Phase 5 acceptance)

- **External reachability:** from another host, `nmap -sU -sS <public-ip>` shows
  **only** `51820/udp` open; everything else filtered/closed.
- **Service confinement:** `systemd-analyze security localcloud.service` scores
  in the "OK"/hardened range; `aa-status` lists the profile enforcing.
- **No privilege:** `ps -o user= -C hypercorn` (or via `systemctl show`) shows
  `localcloud`, not root; `cat /proc/$(pidof -s hypercorn)/status | grep CapEff`
  is near-empty.
- **Kill-switch:** `deploy/scripts/localcloud-killswitch.sh` drops the WG accept
  rule, kills live sessions, and stops the service; re-check `nmap` shows the
  port gone.
- **No swap of secrets:** `systemctl show localcloud.service -p MemorySwapMax`
  is `0`; `LimitCORE` is `0`.
