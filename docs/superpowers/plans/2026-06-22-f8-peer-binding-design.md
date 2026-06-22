# F8 — Bind session tokens to the WireGuard peer pubkey (design, for review)

> **STATUS (2026-06-22): HYBRID adopted — full pubkey-map below is DEFERRED.**
> Architect + security review found: WireGuard `/32` cryptokey routing already
> stops live source-IP takeover, so this map only adds *churn/misconfig
> detection*, contingent on a fresh (restart-bounded) and tamper-proof root-trust
> map file (a NEW attack surface — see security H1). Net: modest defense-in-depth,
> not fundamental hardening. **Owner decision: implement the cheap high-value half
> now and defer the map.**
> **Implemented instead:** the public/unspecified-bind fail-closed guard in
> `config.validate()` (already present; now pinned by `tests/test_config.py`), and
> the peer-identity==`request.remote_addr` model is RATIFIED in `docs/threat-model.md`.
> The full pubkey-map (everything below) is parked here for if peer-churn ever
> becomes a real concern; if revived, it MUST incorporate the review's required
> changes (H1 map-file hardening, H2 production-fail-closed, M1 freshness scoping,
> M3 strict parse-or-die, the SEC-M2 rate-limit-key guardrail, and the honest
> residual). The `init_auth` signature change it needs is a CLAUDE.md hard stop.

_Original design (option B), preserved for a future revival:_

## Problem
`server/auth.py` binds the session token's mandatory `peer` field to `request.remote_addr` (`_get_peer_identity`, used as `peer_pubkey` at login and `expected_peer` at verify). Identity therefore rests entirely on the source IP. Under strict single-tunnel WireGuard with `/32` AllowedIPs this is 1:1 with a peer, but it collapses if the box ever binds off-tunnel, an IP is reused after a peer is removed/re-added, or AllowedIPs is misconfigured. Bind to the actual WireGuard peer **public key** instead.

## Key insight (keeps this small + safe)
The token **already** carries a mandatory non-empty `peer` claim (`create_session_token` line 115/141-142, `verify_session_token` line 219-227). So:
- **No token-format change** — the `peer` *value* changes from an IP string to `wg:<pubkey>`.
- **No function-signature change** — `peer_pubkey`/`expected_peer` params already exist.
- Existing tokens (IP-valued `peer`) simply fail verification after deploy — acceptable (tokens are short-lived; a deploy invalidates them).

## Design

### 1. Static IP→pubkey map (no runtime subprocess)
The WG allowlist is a fixed, console-managed set with `/32` AllowedIPs, so a **static** map is accurate. The sandboxed server (NoNewPrivileges, read-only root) must NOT shell out to `wg` per request, so:
- A deploy-time generator writes `/run/localcloud/wg-peers.map` (or a configured path): lines `"<ip> <pubkey>"`, one per peer, derived from `wg show <iface> allowed-ips` (or parsed from `wg0.conf` `[Peer]` blocks).
- The server loads it **once at startup** into a `dict[str, str]` (ip → pubkey), read-only thereafter (single-worker; fine).
- Regenerate + restart on peer changes (consistent with console-only admin).

### 2. Config-gated (preserves dev/test + all 365 tests)
- New config field `wg_peer_map_path` (env `LOCALCLOUD_WG_PEER_MAP`), default empty.
- New helper `_peer_binding(remote_addr: str) -> str`:
  - **Map configured + ip present** → `f"wg:{pubkey}"`.
  - **Map configured + ip absent** → `""` (caller fails closed — a source IP with no WG peer must not get/keep a token).
  - **Map NOT configured** (dev/test) → `remote_addr` (current behavior, unchanged).
- Login uses `_peer_binding(...)` as `peer_pubkey`; `require_auth` uses it as `expected_peer`. Deterministic per IP, so create and verify agree. The existing `create_session_token` empty-peer `ValueError` + the verify empty-peer hard-fail already give fail-closed on `""`.

### 3. What does NOT change (invariants preserved)
- **SEC-M2**: `remote_addr` remains the SOLE input; the map is *keyed by* `remote_addr`; no forwarded header is ever read. `_get_peer_identity` (rate-limit key) stays `remote_addr`.
- **Timing**: verify adds one O(1) dict lookup — input-independent. Login equalization unchanged (a missing-peer login fails closed through the existing generic-401 path with the same deadline).
- **Single-worker**: map is load-once read-only state.
- No new Python dependency; no runtime subprocess; sandbox-compatible.

### 4. New artifacts
- `server/auth.py`: `_wg_peer_map` module state + `_load_wg_peer_map(path)` + `_peer_binding(remote_addr)`; call `_load_wg_peer_map` from `init_auth`; swap the two `peer_id`→token-binding sites to `_peer_binding(...)` (keep `peer_id` for rate-limiting).
- `server/config.py`: `wg_peer_map_path` field + env read + validation (if set, file must exist + be readable).
- `deploy/scripts/localcloud-gen-peer-map.sh`: generate the map from `wg show <iface> allowed-ips`; a systemd `ExecStartPre` (or a `wg`-reload hook) regenerates it.
- `deploy/systemd/localcloud.service`: add the map path to the service env + an `ExecStartPre=` to regenerate (or document manual regen).
- Tests: map load/parse, `_peer_binding` (configured-hit / configured-miss→"" / unconfigured→ip), and an end-to-end login+request under a configured map (token bound to `wg:<pubkey>`, mismatch fails closed).

### 5. Open questions for review
- **Q1**: map-configured-but-IP-absent → fail closed (proposed) vs fall back to IP? Proposed **fail closed** (an unmapped IP behind an authoritative WG map is anomalous).
- **Q2**: bind to `wg:<pubkey>` alone, or `f"{remote_addr}|wg:{pubkey}"` (both)? Proposed **pubkey alone** — it is strictly stronger (the map already enforces ip↔pubkey), and avoids a token breaking on a benign IP change for the same peer. Reviewer to confirm.
- **Q3**: regeneration trigger — `ExecStartPre` on the service (regen at every (re)start) vs a `wg-quick@wg0` hook. Proposed `ExecStartPre` (simplest; the map is always fresh at service start). Hardware-validated via the acceptance script.

### 6. Hardware-bound part
The real `wg`-derived map + the `/32`-enforcement already live in the acceptance script (`localcloud-acceptance-check.sh`). The code + fallback are fully dev-testable; only the live-WG map generation needs the box.
