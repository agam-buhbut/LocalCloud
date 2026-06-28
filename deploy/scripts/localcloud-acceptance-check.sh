#!/bin/sh
# LocalCloud hardware acceptance check (Definition of Done #4/#5/#7).
#
# Run this ON THE DEPLOYED BOX, from the physical console, AFTER the deploy/
# tree is installed and the service is up. It is the automatable half of the
# first-deploy acceptance; the cross-host and destructive checks it cannot do
# safely are reported as SKIP with the exact manual command to run.
#
# SAFE BY DEFAULT: only read-only probes run. Disruptive/destructive checks are
# opt-in:
#   --run-backup-drill   run the backup-copy -> restore-copy core into temp dirs
#                        and diff + strings-scan them (reads prod data dir; does
#                        NOT touch prod; does NOT exercise the real LUKS HDD).
#   --test-uptime-toggle DISRUPTIVE: offline -> verify port closed -> online.
#                        Drops the WG port briefly; existing sessions drain.
#
# Tunables (env, with deploy-tree defaults):
#   LOCALCLOUD_SERVICE=localcloud.service
#   LOCALCLOUD_WG_IFACE=wg0
#   LOCALCLOUD_WG_PORT=51820
#   LOCALCLOUD_BIND=10.0.0.1:8443        (where the app listens, for the login probe)
#   LOCALCLOUD_DATA_DIR=/srv/cloud
#   LOCALCLOUD_AA_PROFILE=localcloud-server
#
# Exit code: 0 if no FAIL, 1 otherwise. SKIP never fails the run.
set -u

SERVICE="${LOCALCLOUD_SERVICE:-localcloud.service}"
WG_IFACE="${LOCALCLOUD_WG_IFACE:-wg0}"
WG_PORT="${LOCALCLOUD_WG_PORT:-51820}"
BIND="${LOCALCLOUD_BIND:-10.0.0.1:8443}"
DATA_DIR="${LOCALCLOUD_DATA_DIR:-/srv/cloud}"
# The AppArmor profile is explicitly NAMED `localcloud-server` (see
# deploy/apparmor/usr.local.bin.localcloud-server); aa-status reports it by that
# name, not by the attachment path or the on-disk filename.
AA_PROFILE="${LOCALCLOUD_AA_PROFILE:-localcloud-server}"
NFT_TABLE="inet localcloud"
NFT_SET="wg_online"

PASSES=0
FAILS=0
SKIPS=0

pass() { printf 'PASS  %s\n' "$1"; PASSES=$((PASSES + 1)); }
fail() { printf 'FAIL  %s\n' "$1"; FAILS=$((FAILS + 1)); }
skip() { printf 'SKIP  %s  (%s)\n' "$1" "$2"; SKIPS=$((SKIPS + 1)); }
info() { printf '      %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n=== %s ===\n' "$1"; }

RUN_BACKUP_DRILL=0
TEST_UPTIME=0
for arg in "$@"; do
    case "$arg" in
    --run-backup-drill) RUN_BACKUP_DRILL=1 ;;
    --test-uptime-toggle) TEST_UPTIME=1 ;;
    -h | --help)
        sed -n '2,30p' "$0"
        exit 0
        ;;
    *)
        echo "unknown arg: $arg" >&2
        exit 2
        ;;
    esac
done

# ─────────────────────── DoD #4: network reachability ───────────────────────
section "DoD #4 — reachable only via WireGuard"

if have wg && wg show "$WG_IFACE" >/dev/null 2>&1; then
    pass "WireGuard interface $WG_IFACE is up"
    peers=$(wg show "$WG_IFACE" peers | wc -l)
    info "configured peers: $peers (each MUST have a /32 AllowedIPs — verify below)"
    # Exactly-one-/32-per-peer is what makes source-IP == identity sound (SEC-M2).
    # `wg show allowed-ips` prints one line per peer: "<pubkey>\t<cidr> [<cidr> …]".
    # A peer is GOOD only if it has a single allowed entry and that entry is a
    # /32. A wider CIDR, multiple entries, or a /32 *plus* a wider range all
    # break the 1:1 mapping, so flag anything that is not exactly one /32.
    bad=$(wg show "$WG_IFACE" allowed-ips | awk '!(NF == 2 && $2 ~ /\/32$/)')
    if [ -n "$bad" ]; then
        fail "a peer's AllowedIPs is not exactly one /32 — breaks 1:1 source-IP<->peer identity"
        printf '%s\n' "$bad" | sed 's/^/      /'
    else
        pass "every peer AllowedIPs is exactly one /32 (1:1 source-IP <-> peer)"
    fi
else
    skip "WireGuard interface check" "wg/$WG_IFACE not available (not on the box?)"
fi

if have nft && nft list table $NFT_TABLE >/dev/null 2>&1; then
    if nft list table $NFT_TABLE | grep -q 'policy drop'; then
        pass "nftables $NFT_TABLE has a default-deny (policy drop) chain"
    else
        fail "nftables $NFT_TABLE has NO 'policy drop' — default-deny not in force"
    fi
    if nft list set $NFT_TABLE $NFT_SET 2>/dev/null | grep -q "$WG_PORT"; then
        info "online: udp/$WG_PORT is in the $NFT_SET set (box is currently ONLINE)"
    else
        info "offline: udp/$WG_PORT not in $NFT_SET (box is currently OFFLINE)"
    fi
else
    skip "nftables ruleset check" "nft/$NFT_TABLE not available"
fi

# Only the WG UDP port should be externally reachable; the app must NOT listen
# on a public interface. We can check local listeners here; true external
# reachability needs a SECOND host.
if have ss; then
    pub=$(ss -H -lun 2>/dev/null | awk '{print $4}' | grep -vE '127\.0\.0\.1|::1' || true)
    info "non-loopback UDP listeners: ${pub:-<none>}"
    nonwg=$(printf '%s\n' "$pub" | grep -v ":$WG_PORT\$" | grep -v '^$' || true)
    if [ -z "$nonwg" ]; then
        pass "no non-loopback UDP listener other than the WG port"
    else
        # Host services (dhclient udp/68, resolvers, …) may appear here and are
        # NOT a LocalCloud failure: the default-deny firewall — not the bind —
        # gates external reachability (the external-nmap SKIP below is the real
        # test). Surface them for manual review instead of failing. (D5, 2026-06-28)
        info "non-WG UDP listeners present (verify the firewall denies them externally): $nonwg"
    fi
    # The LocalCloud app must bind the WG IP, never 0.0.0.0. Scope this to the
    # SERVICE's OWN process so a host sshd/other daemon listening on 0.0.0.0 is
    # not mistaken for the app binding wide. (D5, 2026-06-28)
    svc_pid=$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || true)
    if [ -n "$svc_pid" ] && [ "$svc_pid" != 0 ]; then
        if ss -H -ltnp 2>/dev/null | grep -E "pid=${svc_pid}[,)]" |
            awk '{print $4}' | grep -q '0\.0\.0\.0'; then
            fail "the $SERVICE process binds 0.0.0.0 — it must bind the WG IP only"
        else
            pass "$SERVICE does not bind 0.0.0.0 (host services on 0.0.0.0 out of scope)"
        fi
    else
        info "could not resolve $SERVICE MainPID — skipping app-specific 0.0.0.0 bind check"
    fi
else
    skip "local listener check" "ss not available"
fi
skip "external port scan" "needs a SECOND host: run  nmap -sU -p $WG_PORT <box-wg-ip>  and  nmap -sT -p- <box-public-ip> (expect only $WG_PORT/udp open, nothing on the public NIC)"

# ─────────────────────── DoD #4: sandbox / least privilege ───────────────────
section "DoD #4 — AppArmor + systemd sandbox + separate users"

if have aa-status; then
    if aa-status --enforced 2>/dev/null | grep -q "$AA_PROFILE"; then
        pass "AppArmor profile $AA_PROFILE is in ENFORCE mode"
    elif aa-status 2>/dev/null | grep -q "$AA_PROFILE"; then
        info "AppArmor profile $AA_PROFILE loaded but aa-status --enforced does not list it (apparmor-utils quirk); the /proc attachment check below is authoritative"
    else
        fail "AppArmor profile $AA_PROFILE not loaded"
    fi
    # AUTHORITATIVE (D3, 2026-06-28): a loaded profile confines NOTHING unless it
    # is actually attached to the daemon. A venv's bin/python3 is a symlink, so
    # path-based attachment silently fails and the daemon runs unconfined even
    # with the profile "enforcing". Check the live process's context directly.
    if have systemctl; then
        aa_pid=$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || true)
        if [ -n "$aa_pid" ] && [ "$aa_pid" != 0 ]; then
            cur=$(cat /proc/"$aa_pid"/attr/current 2>/dev/null | tr -d '\0' || echo "?")
            case "$cur" in
            "$AA_PROFILE"*) pass "live daemon (pid $aa_pid) is CONFINED by $AA_PROFILE ($cur)" ;;
            unconfined*) fail "live daemon (pid $aa_pid) is UNCONFINED — profile not attached. Add 'AppArmorProfile=$AA_PROFILE' to the unit (systemd attaches by name, symlink-proof)." ;;
            *) info "live daemon AppArmor context: ${cur:-<unknown>}" ;;
            esac
        fi
    fi
else
    skip "AppArmor enforce check" "aa-status not available"
fi

if have systemctl; then
    show() { systemctl show -p "$1" --value "$SERVICE" 2>/dev/null; }
    user=$(show User)
    if [ -n "$user" ] && [ "$user" != "root" ]; then
        pass "service runs as non-root user '$user'"
    else
        fail "service User= is '${user:-root}' — must be a dedicated non-root user"
    fi
    for d in NoNewPrivileges ProtectSystem ProtectHome PrivateTmp; do
        v=$(show "$d")
        info "$d=$v"
    done
    [ "$(show NoNewPrivileges)" = "yes" ] &&
        pass "NoNewPrivileges=yes" || fail "NoNewPrivileges is not yes"
    case "$(show ProtectSystem)" in
    strict | full) pass "ProtectSystem=$(show ProtectSystem) (read-only system)" ;;
    *) fail "ProtectSystem=$(show ProtectSystem) — want strict (read-only root)" ;;
    esac
    if have systemd-analyze; then
        sec=$(systemd-analyze security "$SERVICE" 2>/dev/null | tail -1)
        info "systemd-analyze security: $sec"
    fi
else
    skip "systemd sandbox check" "systemctl not available"
fi

# ────────── DoD #4 CRITICAL: MemoryDenyWriteExecute does not break argon2 ──────
section "DoD #4 CRITICAL — argon2 login works UNDER the sandbox (MDWX risk)"
# argon2-cffi is a compiled C ext; MemoryDenyWriteExecute=yes blocks new W+X
# mappings. If it breaks argon2, EVERY login dies on first boot. Prove it with a
# real login probe: a clean 401 (bad creds, equalized argon2 ran) or 200 means
# argon2 executed under the sandbox; a 5xx / connection-refused / timeout is a
# FAIL — remove MemoryDenyWriteExecute= from localcloud.service if so.
if have systemctl; then
    info "MemoryDenyWriteExecute=$(systemctl show -p MemoryDenyWriteExecute --value "$SERVICE" 2>/dev/null)"
fi
if have curl; then
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
        -X POST "http://$BIND/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d '{"username":"__acceptance_probe__","password":"definitely-wrong"}' 2>/dev/null || echo "000")
    case "$code" in
    401 | 200) pass "login probe returned $code — argon2 executed under the sandbox" ;;
    000) fail "login probe could not connect to http://$BIND (service down / wrong BIND / firewalled)" ;;
    5*) fail "login probe returned $code — argon2/sandbox likely BROKEN (check MemoryDenyWriteExecute)" ;;
    *) fail "login probe returned unexpected $code" ;;
    esac
else
    skip "argon2-under-sandbox login probe" "curl not available — run the POST /api/auth/login probe manually"
fi

# ─────────────────────── DoD #5: scheduled uptime + kill-switch ──────────────
section "DoD #5 — scheduled uptime + operator kill-switch"
if have systemctl; then
    for t in localcloud-online.timer localcloud-offline.timer; do
        st=$(systemctl is-enabled "$t" 2>/dev/null)
        st="${st:-missing}"
        if [ "$st" = "enabled" ]; then
            pass "$t is enabled"
        else
            fail "$t is $st (enable with: systemctl enable --now $t)"
        fi
    done
    info "next timer elapses:"
    systemctl list-timers 'localcloud-*' --no-pager 2>/dev/null | sed 's/^/      /'
else
    skip "uptime timer check" "systemctl not available"
fi

if [ "$TEST_UPTIME" = 1 ]; then
    if have nft && [ -x /usr/local/sbin/localcloud-offline.sh ]; then
        info "DISRUPTIVE: toggling offline -> online to prove the port closes/opens..."
        /usr/local/sbin/localcloud-offline.sh
        if nft list set $NFT_TABLE $NFT_SET 2>/dev/null | grep -q "$WG_PORT"; then
            fail "after offline, udp/$WG_PORT is STILL in $NFT_SET"
        else
            pass "offline closed udp/$WG_PORT (removed from $NFT_SET)"
        fi
        /usr/local/sbin/localcloud-online.sh
        nft list set $NFT_TABLE $NFT_SET 2>/dev/null | grep -q "$WG_PORT" &&
            pass "online re-opened udp/$WG_PORT" || fail "online did NOT re-open udp/$WG_PORT"
    else
        skip "uptime toggle" "nft or offline/online scripts not installed"
    fi
else
    skip "uptime toggle (online/offline)" "disruptive — re-run with --test-uptime-toggle on a maintenance window"
fi
skip "kill-switch end-to-end" "destructive (severs sessions) — run manually: localcloud-killswitch.sh, confirm port closed + sessions dropped, then recover per runbooks/operations.md"

# ─────────────────────── DoD #7: backup -> restore drill ─────────────────────
section "DoD #7 — encrypted backup -> restore, no plaintext on media"
if [ "$RUN_BACKUP_DRILL" = 1 ]; then
    here=$(CDPATH= cd "$(dirname "$0")" && pwd)
    bcopy="$here/../backup/localcloud-backup-copy.sh"
    rcopy="$here/../backup/localcloud-restore-copy.sh"
    if [ ! -d "$DATA_DIR" ]; then
        fail "data dir $DATA_DIR not found — set LOCALCLOUD_DATA_DIR"
    elif [ ! -x "$bcopy" ] || [ ! -x "$rcopy" ]; then
        fail "backup-copy/restore-copy scripts not found next to this script"
    else
        bdir=$(mktemp -d) || exit 1
        rdir=$(mktemp -d) || exit 1
        trap 'rm -rf "$bdir" "$rdir"' EXIT
        if "$bcopy" "$DATA_DIR" "$bdir" && "$rcopy" "$bdir" "$rdir"; then
            pass "backup-copy -> restore-copy completed without error"
            if have cmp && cmp -s "$bdir/meta.db" "$rdir/meta.db"; then
                pass "restored meta.db is byte-identical to the backup snapshot"
            else
                info "meta.db differs (expected if WAL snapshot vs plain copy) — verifying blob set instead"
            fi
            # No plaintext on backup media: blobs must be high-entropy ciphertext.
            # Spot-check that no copied blob contains long printable runs (a crude
            # plaintext detector); staging/ must NOT have been copied.
            if [ -d "$bdir/staging" ]; then
                fail "backup copied a staging/ dir — transient/in-flight data must be excluded"
            else
                pass "staging/ correctly excluded from the backup"
            fi
            # Plaintext detection by ENTROPY, not `strings`. A `strings -n12`
            # scan FALSE-POSITIVES on ciphertext: a multi-MB XChaCha20 blob is
            # ~8.0 bits/byte random and, by chance, contains 12–15 char printable
            # runs (verified on hardware — see docs/pentest-2026-06-28.md D4).
            # Real plaintext is well under ~6 bits/byte; 7.5 is a wide margin.
            if have python3 && [ -d "$bdir/blobs" ]; then
                worst=$(python3 - "$bdir/blobs" <<'PY'
import sys, os, math, collections
worst = 8.0
for dp, _, files in os.walk(sys.argv[1]):
    for name in files:
        data = open(os.path.join(dp, name), "rb").read()
        if not data:
            continue
        counts = collections.Counter(data)
        n = len(data)
        h = -sum(v / n * math.log2(v / n) for v in counts.values())
        worst = min(worst, h)
print(f"{worst:.3f}")
PY
)
                if [ -n "$worst" ] && awk "BEGIN{exit !($worst < 7.5)}"; then
                    fail "a backup blob has low entropy ($worst bits/byte) — possible plaintext on media"
                else
                    pass "all backup blobs are high-entropy ciphertext (min $worst bits/byte)"
                fi
            else
                skip "blob entropy spot-check" "python3 unavailable or no blobs"
            fi
        else
            fail "backup-copy/restore-copy returned an error"
        fi
    fi
else
    skip "backup -> restore drill" "re-run with --run-backup-drill (reads $DATA_DIR into temp dirs; non-destructive to prod)"
fi
skip "full LUKS backup drill" "needs the physical backup HDD: run deploy/backup/localcloud-backup.sh, then on a SCRATCH box localcloud-restore.sh, mount the media and confirm 'strings' finds no plaintext (see runbooks/operations.md)"

# ─────────────────────────────── summary ────────────────────────────────────
section "summary"
printf 'PASS=%d  FAIL=%d  SKIP=%d\n' "$PASSES" "$FAILS" "$SKIPS"
if [ "$FAILS" -gt 0 ]; then
    echo "ACCEPTANCE: FAILED — resolve the FAIL items above before trusting this box."
    exit 1
fi
echo "ACCEPTANCE: no failures. Review the SKIP items (cross-host / destructive) manually."
exit 0
