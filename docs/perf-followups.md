# GIH performance — further improvement analysis

Follow-up to PR #1 (bounded parallel BFS). PR #1 already: memoized tool checks,
parallelized BFS levels with main-thread SQLite writes, parallelized per-artifact
external tools, added a wall-clock deadline + artifact budget, tightened timeouts,
and added per-stage timing logs. A representative run dropped from "hours" to ~21s
in this environment — but that run had most external CLI tools disabled and few
platforms reachable. The items below matter once real tool sets and large fan-outs
are enabled, and are ordered by expected ROI.

## Tier 1 — highest impact / lowest risk

### 1. Fix nested, uncontrolled thread pools (oversubscription)
Today parallelism is stacked without a shared bound:
`run_investigation` level pool (`max_parallel_workers`, 15) → each `_process_artifact`
→ `_process_external_tools` opens its *own* `ThreadPoolExecutor`, **and** `username_search`
opens `search_usernames_batch`'s pool, **and** `google_dorks` opens its own worker pool,
**and** plugins may too. Worst case ≈ 15 × (tools) × (platforms) live threads → GIL/context-switch
thrash, connection-pool contention, and unpredictable latency.

Fix: create **one** module-level bounded `ThreadPoolExecutor` (size ≈ CPU/network budget)
and submit all I/O tasks to it, or pass a shared executor down into `_process_artifact` /
`_process_external_tools`. Avoid opening a new pool per artifact per tool. This alone
usually gives the biggest win once fan-out is large.

### 2. Global rate limiter sleeps while holding the lock
`http_client._apply_rate_limit()` does `time.sleep(min_interval - delta)` **inside**
`with _rate_limit_lock:`. Every request routed through `make_request_with_timing` is
therefore serialized to ~`1/min_request_interval` req/s globally (10 req/s at the 0.1s
default), negating HTTP parallelism.

Fix: compute the wait under the lock, release, then sleep; or use a per-host token
bucket so unrelated hosts don't block each other. (Note: `username_search._check_platform`
calls `session.get` directly and bypasses this path — inconsistent; unify on one HTTP entry
point so pooling *and* fair rate limiting both apply.)

### 3. Route Google Dorks through the pooled session
`google_dorks.py` calls `requests.get`/`requests.post` directly (module-level), so it
opens a fresh TCP+TLS connection per request and skips the tuned retry/keep-alive adapter
in `http_client.get_http_session()`. Switching to the shared session gives connection reuse
(big latency win against the same host) and consistent retry/timeout behavior.

### 4. Memoize external-tool + module results per (target) within a run
The BFS re-discovers the same domain/email/username from multiple parents; each occurrence
re-runs the same subprocess/HTTP work before dedup happens at persistence time. Add a
process-scoped cache keyed by `(tool, analysis, value)` around `run_tool_analysis` (and the
Google Dorks / username paths), so a target is investigated at most once per run — complements
the `seen` set (which only prevents re-queue, not re-work within a level).

## Tier 2 — structural

### 5. CPU-bound image work needs processes, not threads
`image_match` / `face_recognition` (dlib) is CPU-bound; threads don't help under the GIL and
can starve I/O threads. Run face encoding/matching in a `ProcessPoolExecutor`, and keep the
heavy `import face_recognition` lazy (only when an image artifact is actually processed) to cut
startup cost when images aren't in scope.

### 6. Consider async I/O for the platform-check fan-out
Username checks are hundreds of small, independent HTTP calls — the classic case where
`asyncio`+`aiohttp`/`httpx` scales far better (and cheaper) than a thread-per-request pool.
Even keeping threads, size `pool_maxsize` and the executor to the real concurrency so the pool
isn't exceeded (`pool_block=False` currently silently discards overflow connections).

### 7. Subprocess spin-up + per-host circuit breaker
External CLI tools pay process-spawn cost every call. Two mitigations: (a) skip tools already
known unavailable earlier (memoized checker helps, but also gate on `config.enabled`), and
(b) a per-host/per-tool circuit breaker that short-circuits a target after N consecutive
timeouts/errors so one hung host can't repeatedly burn the timeout budget.

### 8. SQLite: WAL + indexes + batched inserts
- Enable `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;` on the connection for faster
  commits.
- Ensure indexes on `artifacts(investigation_id, type, value)` and `links(investigation_id,
  source_artifact)` — dedup lookups and `get_artifacts`/`get_links` in finalize scan these.
- Batch per-level inserts with `executemany` inside the single per-level transaction (already
  committing once per level, which is good).

## Tier 3 — correctness bugs that waste time

### 9. Two pre-existing runtime errors surfaced during testing
Not introduced by PR #1, but they raise/retry on every relevant artifact:
- `username_search`: `KeyError: 'expected_status'` for Reddit/GitLab (platform config missing
  the key the `api_status`/`api_json` branches read).
- `wayback_machine` integration: `object has no attribute 'search_username'`.
Fixing these removes wasted exception/retry cycles and restores the results those paths should
contribute.

## Measurement / guardrails
- The new per-level timing logs are the right hook; add an end-of-run **summary table**
  (per-tool total time, call count, timeout count) so the dominant cost is obvious per run and
  regressions are visible.
- Add a small benchmark harness (fixed seed set, tools stubbed to record call counts + fake
  latency) so these changes can be compared without live network — extends the existing
  `tests/test_orchestrator.py` stubbing approach.

## Suggested order
1 → 2 → 3 → 4 (throughput, all low-risk), then 5/6 (fan-out scaling), 8 (DB), 7, and 9 alongside.
