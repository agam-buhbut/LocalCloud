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
- [ ] Lockfiles committed (`rust/keycore/Cargo.lock`; Python — see below).

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

## Open item — Python lockfile (DEPENDENCY DECISION REQUIRED)

`rust/keycore/Cargo.lock` is committed; there is **no committed Python
lockfile** yet. A reproducible Python install needs a hash-pinned lockfile,
which requires a resolver tool (`pip-tools`/`pip-compile` or `uv`). Adding one
is a **new dev dependency** and must be approved first (per the dependencies
policy), so it is intentionally NOT added here.

Once approved, the intended step is:
```sh
pip install pip-tools           # add to [project.optional-dependencies].dev
pip-compile --generate-hashes -o requirements.lock pyproject.toml
git add requirements.lock
# CI: `pip install --require-hashes -r requirements.lock` before `pip install -e .`
```
Until then, reproducibility rests on the audited, upper-bounded ranges in
`pyproject.toml` + `pip-audit` in CI.
