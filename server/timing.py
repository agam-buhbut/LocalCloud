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

# Constant timing budget for every equalized endpoint, in seconds. ~150 ms
# is in the same ballpark as a server-side Argon2id verify on commodity
# hardware, so a rate-limit / unknown-user reject is indistinguishable from
# a real verify. The login path historically used this exact value as its
# flat post-reject sleep; share/unshare/directory use it as a deadline.
TIMING_BUDGET_S: float = 0.150


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
