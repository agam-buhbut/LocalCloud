# LocalCloud - Typed Application State
#
# A frozen, fully-typed snapshot of the config/identity singletons the
# request handlers depend on. Built once in create_app and stored on
# ``app.extensions["localcloud"]`` so handlers read a concrete, typed
# object instead of module-global ``Database | None`` / ``str`` slots
# (which forced type-checker suppressions throughout auth.py and
# storage.py).
#
# Scope (ARCH-H2 / Phase 1A): only the config + identity singletons move
# here. The intentionally process-global rate limiter (``_composite_*``
# in auth.py) and the Argon2 semaphore stay module-level — they are
# single-worker process-shared state, out of scope for this refactor.

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from quart import Quart, current_app, g

from server.database import Database

# Key under which the AppState lives in ``app.extensions``. A single
# namespaced key keeps it from colliding with any Quart/extension state.
_EXTENSION_KEY = "localcloud"


@dataclass(frozen=True)
class AppState:
    """Immutable, fully-typed snapshot of per-app config and dependencies.

    Built once by ``create_app`` and read by handlers via ``app_state()``.
    Frozen so a handler cannot accidentally mutate shared app state.
    """

    db: Database
    blob_dir: str
    staging_dir: str
    staging_expiry: int
    max_chunk_size: int
    session_secret: str
    session_lifetime: int
    rate_limit_max: int
    rate_limit_window: int


@dataclass(frozen=True)
class Identity:
    """Authenticated caller identity, set on ``g`` by ``require_auth``.

    Replaces the previously dynamically-attached ``request.user_id`` /
    ``request.username`` attributes, which were untyped and required a
    type-checker suppression at every read site.
    """

    user_id: str
    username: str


def store_app_state(app: Quart, state: AppState) -> None:
    """Attach ``state`` to the app's extension registry."""
    app.extensions[_EXTENSION_KEY] = state


def app_state() -> AppState:
    """Return the current app's typed ``AppState``.

    Must be called inside an application/request context.

    Raises:
        KeyError: if the state was never installed (create_app not run).
    """
    return cast(AppState, current_app.extensions[_EXTENSION_KEY])


def current_identity() -> Identity:
    """Return the authenticated caller's ``Identity`` for this request.

    Set by ``require_auth`` before the wrapped handler runs, so any
    handler guarded by ``@require_auth`` may rely on it.

    Raises:
        RuntimeError: if called outside a request that passed through
            ``require_auth`` (no identity bound on ``g``).
    """
    identity = getattr(g, "identity", None)
    if identity is None:
        raise RuntimeError("current_identity() called without require_auth")
    return cast(Identity, identity)
