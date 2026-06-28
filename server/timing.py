# LocalCloud - Timing-equalization helpers
#
# Single source of truth for the constant-deadline pattern used by every
# timing-equalized endpoint (login, share/unshare, directory lookup). These
# endpoints must take a fixed minimum wall-clock time so that an attacker
# cannot distinguish "row exists" from "no row" by latency (username / file
# enumeration oracles).
#
# CRITICAL: the equalization is achieved by (a) running the SAME work shape
# on both branches and (b) capping residual variance with a constant
# deadline. This module owns ONLY the deadline cap and its budget constant;
# the per-endpoint "same work shape" stays at each call site. Changing
# TIMING_BUDGET_S changes every equalized endpoint's floor — keep it fixed.

from __future__ import annotations

import asyncio
import time

# Timing budget (seconds) for every equalized endpoint: a FLOOR that
# calibrate_budget() raises at startup to the deployment's real Argon2id cost.
# 150 ms was the original flat value, assuming "Argon2id verify ~= 150 ms on
# commodity hardware". The 2026-06-28 hardware pentest (P1) measured ~250 ms on
# the target CPU, so the non-Argon2 paths (rate-limit / early reject) finished
# ~100 ms sooner than a real verify and leaked rate-limit state by latency. The
# server now calibrates this UP from a measured Argon2id op at startup so every
# equalized path shares one budget >= the real verify cost. share / unshare /
# directory use it as a deadline; the login path now does too (see auth.login).
TIMING_BUDGET_S: float = 0.150

# Headroom over the measured Argon2id cost. Covers CPU/scheduler/contention
# variance so a real verify rarely overruns the budget (an overrun re-opens the
# gap for that one request). Login is not latency-sensitive, so padding every
# auth to ~Argon2id*MARGIN is acceptable.
_BUDGET_MARGIN: float = 1.30


async def sleep_until_deadline(started: float, budget: float | None = None) -> None:
    """Sleep so the elapsed time since ``started`` reaches ``budget``.

    Caps residual timing variance between the "row exists" and "no row"
    branches of an equalized endpoint. The caller MUST snapshot
    ``started = time.monotonic()`` BEFORE the existence-dependent work
    (length check, canonicalization, DB lookup, write transaction) so all
    of that latency lives inside the constant envelope.

    A no-op when the work already overran the budget — the cap is a floor,
    never a ceiling.

    Args:
        started: ``time.monotonic()`` captured before the variable work.
        budget: Deadline in seconds. ``None`` (the default) reads the
            module-level ``TIMING_BUDGET_S`` AT CALL TIME — so a test that
            monkeypatches the constant is honored (a bound default argument
            would not be). A caller may pass an explicit per-endpoint budget
            (the directory passes its own monkeypatchable attribute).
    """
    if budget is None:
        budget = TIMING_BUDGET_S
    remaining = budget - (time.monotonic() - started)
    if remaining > 0:
        await asyncio.sleep(remaining)


def calibrate_budget(measured_argon2_seconds: float) -> float:
    """Raise the equalization budget to cover the real Argon2id cost. (P1)

    Sets the module-global ``TIMING_BUDGET_S`` to
    ``max(current, measured * _BUDGET_MARGIN)``. It never LOWERS the floor, so a
    fast CPU keeps the 150 ms minimum while a slow one is padded up to match its
    own verify cost — closing the latency gap between the Argon2id paths and the
    early-reject / rate-limit paths that leaked rate-limit state (pentest P1).
    Monotonic and idempotent: a later call with a smaller (or non-positive)
    measurement is a no-op. Returns the resulting budget.

    Args:
        measured_argon2_seconds: wall-clock of one representative Argon2id op
            (hash or verify — equivalent cost for the same params), measured
            once at startup.
    """
    global TIMING_BUDGET_S
    if measured_argon2_seconds > 0:
        TIMING_BUDGET_S = max(TIMING_BUDGET_S, measured_argon2_seconds * _BUDGET_MARGIN)
    return TIMING_BUDGET_S
