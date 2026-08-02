"""Process-wide concurrency bound for outbound I/O work.

The investigation runs several *nested* thread pools: the BFS level pool, the
per-artifact external-tool pool, the per-username platform-check pool, and the
Google Dorks pool. Multiplied together these can spawn far more concurrent
network/subprocess operations than is useful, causing GIL/context-switch
thrash and connection-pool contention.

Rather than rewire every pool into a single executor (which risks the classic
pool-within-pool deadlock, where a coordinating task waits on subtasks that
need the same exhausted pool), we bound the *actual* outbound work with a
single global semaphore acquired only at leaf operations (an HTTP request or a
subprocess run). Coordinating tasks never hold the slot while waiting on their
children, so no deadlock is possible, while total concurrent I/O stays capped
regardless of how the pools nest.
"""

import logging
import threading
from contextlib import contextmanager
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

_DEFAULT_MAX_CONCURRENT_IO = 32

_semaphore: Optional[threading.BoundedSemaphore] = None
_semaphore_size: Optional[int] = None
_lock = threading.Lock()


def _resolve_max_concurrent_io() -> int:
    """Resolve the configured global I/O concurrency bound."""
    try:
        from src.config.loader import get_config

        config = get_config()
        inv = config.get("investigation", {}) or {}
        value = inv.get("max_concurrent_io", _DEFAULT_MAX_CONCURRENT_IO)
        return max(1, int(value))
    except Exception:
        return _DEFAULT_MAX_CONCURRENT_IO


def configure(max_concurrent_io: Optional[int] = None) -> None:
    """(Re)initialize the global I/O semaphore.

    Called once at the start of an investigation. Passing an explicit value
    overrides the configured default (used mainly by tests).
    """
    global _semaphore, _semaphore_size
    size = max_concurrent_io if max_concurrent_io is not None else _resolve_max_concurrent_io()
    size = max(1, int(size))
    with _lock:
        _semaphore = threading.BoundedSemaphore(size)
        _semaphore_size = size
    logger.debug("Configured global I/O concurrency bound: %d", size)


def _get_semaphore() -> threading.BoundedSemaphore:
    global _semaphore
    if _semaphore is None:
        with _lock:
            if _semaphore is None:
                size = _resolve_max_concurrent_io()
                _semaphore = threading.BoundedSemaphore(size)
                globals()["_semaphore_size"] = size
    return _semaphore


@contextmanager
def io_slot() -> Iterator[None]:
    """Acquire one global I/O slot for the duration of a leaf operation.

    Use only around actual outbound work (HTTP request, subprocess). Never hold
    a slot while waiting on child tasks that also need one.
    """
    sem = _get_semaphore()
    sem.acquire()
    try:
        yield
    finally:
        sem.release()
