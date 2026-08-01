"""Tests for Tier 1 performance follow-ups: I/O concurrency bound, tool-result
memoization, and the rate-limiter no longer sleeping under its lock."""

import threading
import time

from src.utils import concurrency


def test_io_slot_bounds_concurrency():
    """io_slot() must cap the number of simultaneous holders to the configured size."""
    concurrency.configure(2)

    active = 0
    peak = 0
    lock = threading.Lock()
    barrier_release = threading.Event()

    def worker():
        nonlocal active, peak
        with concurrency.io_slot():
            with lock:
                active += 1
                peak = max(peak, active)
            barrier_release.wait(timeout=1.0)
            with lock:
                active -= 1

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    time.sleep(0.2)
    barrier_release.set()
    for t in threads:
        t.join(timeout=2.0)

    assert peak <= 2


def test_configure_resizes_semaphore():
    concurrency.configure(5)
    assert concurrency._semaphore_size == 5
    concurrency.configure(1)
    assert concurrency._semaphore_size == 1


def test_run_tool_analysis_memoized(monkeypatch):
    """Repeated (tool, analysis, target) calls run the integration once per run."""
    from src.modules import external_tools

    external_tools.clear_tool_analysis_cache()

    calls = []

    class _FakeIntegration:
        # run_tool_analysis references every tool's method on the selected
        # integration when building its dispatch table, so satisfy those lookups
        # with no-op callables; only search_username is actually invoked here.
        def search_username(self, target):
            calls.append(target)
            return external_tools.ToolResult(tool_name="sherlock", success=True, output="ok")

        def __getattr__(self, name):
            return lambda *a, **k: external_tools.ToolResult(
                tool_name="sherlock", success=False, output=""
            )

    monkeypatch.setattr(
        external_tools, "get_tool_integrations", lambda: {"sherlock": _FakeIntegration()}
    )

    r1 = external_tools.run_tool_analysis("sherlock", "username_search", "alice")
    r2 = external_tools.run_tool_analysis("sherlock", "username_search", "alice")
    external_tools.run_tool_analysis("sherlock", "username_search", "bob")

    assert r1 is r2  # cached instance returned
    assert calls == ["alice", "bob"]  # "alice" resolved once, "bob" once

    external_tools.clear_tool_analysis_cache()
    external_tools.run_tool_analysis("sherlock", "username_search", "alice")
    assert calls == ["alice", "bob", "alice"]  # cache cleared -> re-run


def test_rate_limit_does_not_serialize_under_lock(monkeypatch):
    """_apply_rate_limit must release the lock before sleeping.

    With the lock held during sleep, N concurrent callers would take
    ~N*interval wall-clock; releasing first lets them overlap so the lock is
    never held while sleeping.
    """
    from src.utils import http_client

    monkeypatch.setattr(http_client, "_get_http_config", lambda: {"min_request_interval": 0.05})
    http_client._last_request_time = 0

    lock_held_during_sleep = {"value": False}
    real_sleep = time.sleep

    def instrumented_sleep(seconds):
        # If the global rate-limit lock is held here, the fix is not in place.
        acquired = http_client._rate_limit_lock.acquire(blocking=False)
        if acquired:
            http_client._rate_limit_lock.release()
        else:
            lock_held_during_sleep["value"] = True
        real_sleep(min(seconds, 0.05))

    monkeypatch.setattr(http_client.time, "sleep", instrumented_sleep)

    threads = [threading.Thread(target=http_client._apply_rate_limit) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=2.0)

    assert lock_held_during_sleep["value"] is False
