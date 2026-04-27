"""
Shared helpers for tests that talk to flaky 3rd-party services.

The PNP server we test against (DEST) is real public infrastructure --
it goes up, down, and hits per-IP quotas. Tests that fire one request
and fail on the first transient error gate-halt the matrix on
genuine ENV issues that any single retry would have absorbed.

Mirrors p2pd/tests/server_retry_helpers.py one-to-one so the pattern
is identical across both repos -- if one is improved the other should
follow.
"""
from typing import Any, Callable, Iterable, Optional
import asyncio


# Errors we treat as "try again with a different server / name".
# Application errors (KeyError, AssertionError, ValueError) are NOT
# in this set so a real client bug still raises out of the retry loop.
TRANSIENT_ERRORS = (OSError, ConnectionError, asyncio.TimeoutError)


async def with_server_retry(
    coro_factory: Callable[[], Any],
    attempts: int = 3,
    pause: float = 0.5,
    extra_errors: Optional[tuple] = None,
) -> Any:
    """Run coro_factory() up to attempts times, retrying on transient errors.

    coro_factory is a zero-arg callable that returns a fresh coroutine
    each call. Retries on (OSError, ConnectionError, TimeoutError) plus
    any extra exception types in extra_errors. Use extra_errors to add
    e.g. namebump's response-rejection signals to the retry set.

    pause is the delay between retries (seconds). Linear, not
    exponential -- we're trying alternates not waiting out a backoff.
    """
    errors = TRANSIENT_ERRORS
    if extra_errors:
        errors = errors + tuple(extra_errors)

    last_exc = None
    for i in range(attempts):
        try:
            return await coro_factory()
        except errors as exc:
            last_exc = exc
            if i + 1 < attempts:
                await asyncio.sleep(pause)
    if last_exc is not None:
        raise last_exc
    raise ConnectionError("with_server_retry: all attempts exhausted")


async def try_servers(
    servers: Iterable[Any],
    factory: Callable[[Any], Any],
    extra_errors: Optional[tuple] = None,
) -> Any:
    """Walk servers, return the first factory(server) that succeeds.

    factory(server) is awaitable; treat (OSError, ConnectionError,
    TimeoutError) plus extra_errors as "try the next server". When
    every server fails, raise the last error so test code sees a
    meaningful exception (and can self.skipTest with ENV reason).
    """
    errors = TRANSIENT_ERRORS
    if extra_errors:
        errors = errors + tuple(extra_errors)

    server_list = list(servers)
    if not server_list:
        raise ValueError("try_servers: empty server list")

    last_exc = None
    for server in server_list:
        try:
            return await factory(server)
        except errors as exc:
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    raise ConnectionError("try_servers: every server failed")
