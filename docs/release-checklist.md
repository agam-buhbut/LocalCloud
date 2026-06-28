# Release checklist & Definition of Done

## Definition of Done (per release)

**Application layer (verifiable in this repo):**
- [ ] Full toolchain green: `black --check . && isort --check . && ruff check .
      && pylint client server shared && pyright && pytest -q`.
- [ ] Rust green: `cargo fmt --check`, `cargo clippy -- -D warnings`,
      `cargo test` (manifest `rust/keycore/Cargo.toml`).
- [ ] Supply chain clean: `pip-audit` and `cargo audit` pass in CI; SBOMs
      generated (artifacts).
- [ ] Property tests pass (nonce uniqueness, key isolation, fail-on-corruption).
- [ ] Key-rotation tests pass (`tests/test_key_rotation.py`).
- [ ] Backup/restore core tests pass (`tests/test_backup_restore.py`).
- [ ] `CHANGELOG.md` updated; version bumped.
- [ ] Lockfiles committed and current (`rust/keycore/Cargo.lock`, `uv.lock`;
      CI gates `uv lock --check` for drift).

**Deployment layer (verifiable only on the box — UNVALIDATED in CI):**
- [ ] `nmap` from an external host shows **only** the WG UDP port.
- [ ] `systemd-analyze security localcloud.service` is in the hardened range;
      `aa-status` shows the AppArmor profile enforcing.
- [ ] Daemon runs as `localcloud`, caps near-empty, `LimitCORE=0`,
      `MemorySwapMax=0`.
- [ ] Kill-switch closes the port and severs sessions (re-check with `nmap`).
- [ ] backup→wipe→restore drill reproduces a working server; backup media
      plaintext spot-check passes.
- [ ] LUKS2 + encrypted LVM; console-only unlock; backup HDD never auto-mounted.

**Process:**
- [ ] Threat model (`docs/threat-model.md`) reviewed against the release.
- [ ] Runbooks current (`docs/runbooks/`).
- [ ] Final internal security review pass.
- [ ] **External security audit recommended before storing any real data.**

## Release steps

1. Bump version in `pyproject.toml` and `rust/keycore/Cargo.toml`; update
   `CHANGELOG.md` (move Unreleased → the new version + date).
2. Reproducible extension build: `maturin build --release -m
   rust/keycore/Cargo.toml` on the pinned toolchain (record the rustc version
   in the release notes).
3. Run the full DoD above. Tag only when every application-layer box is checked
   and the deployment boxes are verified on the target box.

## Python lockfile — RESOLVED

Both lockfiles are committed: `rust/keycore/Cargo.lock` and `uv.lock`. The
Python dependency-lock decision was made in favour of `uv`: `uv.lock` is the
hash-pinned, reproducible source of truth, regenerated with `uv lock` after any
`pyproject.toml` change. CI fails the build if it has drifted
(`uv lock --check`, see `.github/workflows/ci.yml`). Recreate the environment
with `uv sync --extra dev`. `pip-audit` over the locked set remains the
supply-chain gate.
