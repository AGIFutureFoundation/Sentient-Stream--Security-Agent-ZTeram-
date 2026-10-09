"""
Sentinel Stream — async batch inserter for ClickHouse.

Background flushes every 1s. Targets ≥10k events/sec sustained.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import clickhouse_connect

logger = logging.getLogger(__name__)

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
FLUSH_INTERVAL_SEC = float(os.environ.get("FLUSH_INTERVAL_SEC", "1.0"))
BATCH_MAX_SIZE = int(os.environ.get("BATCH_MAX_SIZE", "5000"))


class ClickHouseInserter:
    """Async batch inserter. Pushes events to sentinel_events table every 1s."""

    def __init__(self) -> None:
        self._client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USER,
            password=CLICKHOUSE_PASSWORD,
        )
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._flusher_task: asyncio.Task | None = None
        self._total_inserted = 0
        self._total_flushes = 0

    async def start(self) -> None:
        """Start the background flush task."""
        self._flusher_task = asyncio.create_task(self._flush_loop())
        logger.info("Inserter started. flush_interval=%ss batch_max=%s", FLUSH_INTERVAL_SEC, BATCH_MAX_SIZE)

    async def stop(self) -> None:
        """Flush remaining events and stop the background task."""
        if self._flusher_task:
            self._flusher_task.cancel()
            try:
                await self._flusher_task
            except asyncio.CancelledError:
                pass
        await self._flush_pending()
        self._client.close()
        logger.info("Inserter stopped. total_inserted=%s total_flushes=%s", self._total_inserted, self._total_flushes)

    async def put(self, event: dict[str, Any]) -> None:
        """Enqueue an event for batched insertion."""
        await self._queue.put(event)

    async def _flush_loop(self) -> None:
        """Background loop that flushes the queue on an interval."""
        while True:
            await asyncio.sleep(FLUSH_INTERVAL_SEC)
            try:
                await self._flush_pending()
            except Exception as e:  # noqa: BLE001
                logger.error("Flush failed: %s", e)

    async def _flush_pending(self) -> None:
        """Drain the queue and insert as a single batch."""
        if self._queue.empty():
            return
        batch: list[dict[str, Any]] = []
        while not self._queue.empty() and len(batch) < BATCH_MAX_SIZE:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if not batch:
            return

        # Map dict → column arrays
        columns = [
            "ts", "agent_id", "app_id", "event_type", "tool_name",
            "payload_hash", "payload", "tokens_in", "tokens_out",
            "user_id", "session_id", "risk_score", "flags",
        ]
        rows = [[e.get(c, "") if c != "event_type" else _event_type_id(e.get(c))
                 for c in columns] for e in batch]

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: self._client.insert("sentinel_events", rows, column_names=columns),
        )
        self._total_inserted += len(batch)
        self._total_flushes += 1
        logger.debug("Flushed %s events (total=%s)", len(batch), self._total_inserted)


def _event_type_id(name: str | None) -> int:
    """Map event_type string → Enum8 id (matches schema)."""
    return {
        "prompt": 1, "tool_call": 2, "tool_response": 3,
        "model_response": 4, "retrieval": 5, "action": 6,
    }.get(name or "", 0)


# --- hacker-bob session ingestion (NEW) ------------------------------------
# See INTEGRATION.md §3. Tails hacker-bob's per-session session-events.jsonl
# and maps each line to a Sentinel Stream event, replacing the synthetic
# generator with real CVE-graded offensive traffic.

# Map hacker-bob tool names → Sentinel Stream event_type + tool_name
BOB_TOOL_MAP: dict[str, tuple[str, str]] = {
    "bob_http_scan": ("tool_call", "http.scan"),
    "bob_http_confirm": ("tool_call", "http.confirm"),
    "bob_http_xss_confirm": ("tool_call", "http.xss"),
    "bob_http_cors_confirm": ("tool_call", "http.cors"),
    "bob_http_idor_confirm": ("tool_call", "http.idor"),
    "bob_nuclei_scan": ("tool_call", "nuclei.scan"),
    "bob_browser_navigate": ("tool_call", "browser.navigate"),
    "bob_browser_click": ("tool_call", "browser.click"),
    "bob_browser_type": ("tool_call", "browser.type"),
    "bob_browser_snapshot": ("tool_call", "browser.snapshot"),
    "bob_repo_check": ("tool_call", "repo.check"),
    "bob_repo_docker_run": ("tool_call", "repo.docker"),
    "bob_static_scan": ("tool_call", "static.scan"),
    "bob_init_session": ("action", "session.init"),
    "bob_advance_session": ("action", "session.advance"),
    "bob_record_candidate_claim": ("action", "claim.record"),
    "bob_write_grade_verdict": ("action", "grade.write"),
    "bob_export_security_hub_finding": ("action", "asff.export"),
    "bob_query_belief_signals": ("retrieval", "belief.query"),
    "bob_read_session_nucleus": ("retrieval", "nucleus.read"),
}


def map_bob_event_to_sentinel(bob_event: dict[str, Any]) -> dict[str, Any]:
    """Convert a hacker-bob session-events.jsonl line to a Sentinel Stream event.

    hacker-bob events have shape:
        { "ts": "...", "tool": "bob_http_scan", "session_id": "...",
          "args": {...}, "result": {...}, "latency_ms": 42 }

    Sentinel Stream events have shape:
        { "ts": "...", "agent_id": "...", "event_type": "tool_call",
          "tool_name": "http.scan", "payload": "...", ... }
    """
    tool = bob_event.get("tool", "unknown")
    event_type, sentinel_tool = BOB_TOOL_MAP.get(tool, ("action", tool))

    # The agent_id is the hacker-bob session_id (one "agent" per pentest session)
    agent_id = "bob:" + (bob_event.get("session_id", "unknown")[:24] or "unknown")

    # Payload: JSON-serialize args + result snippet
    args = bob_event.get("args", {})
    result = bob_event.get("result", {})
    payload = json.dumps({"tool": tool, "args": args, "result_preview": str(result)[:500]})

    # Flag if the result contains an untrusted-data envelope
    flags: list[str] = []
    if "<<UNTRUSTED_DATA" in payload:
        flags.append("has_untrusted_envelope")
    if "<<END_UNTRUSTED_DATA" in payload:
        flags.append("untrusted_envelope_closed")

    return {
        "ts": bob_event.get("ts") or _now_iso(),
        "agent_id": agent_id,
        "app_id": "hacker-bob",
        "event_type": event_type,
        "tool_name": sentinel_tool,
        "payload": payload,
        "tokens_in": bob_event.get("tokens_in", 0),
        "tokens_out": bob_event.get("tokens_out", 0),
        "user_id": "hacker-bob",
        "session_id": bob_event.get("session_id", ""),
        "risk_score": float(bob_event.get("risk_score", 0.0)),
        "flags": flags,
    }


async def tail_bob_sessions(
    session_root: Path | None = None,
    inserter: "ClickHouseInserter | None" = None,
) -> int:
    """Tail all hacker-bob session-events.jsonl files and ingest into ClickHouse.

    Replaces the synthetic generator with real CVE-graded offensive traffic.
    Returns the number of events ingested.

    Args:
        session_root: Path to ~/hacker-bob-sessions. Defaults to env var or ~.
        inserter: Existing ClickHouseInserter to reuse. Creates one if None.
    """
    root = session_root or Path(os.environ.get(
        "BOB_SESSION_ROOT",
        str(Path.home() / "hacker-bob-sessions"),
    ))
    if not root.exists():
        logger.warning("hacker-bob session root not found: %s", root)
        return 0

    if inserter is None:
        inserter = await get_inserter()

    engine = None
    try:
        from sentinel.detect import get_engine
        engine = get_engine()
    except Exception:
        pass  # detection optional during tailing

    count = 0
    for events_file in root.glob("*/session-events.jsonl"):
        logger.info("Tailing %s", events_file)
        for line in events_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                bob_event = json.loads(line)
            except json.JSONDecodeError:
                continue
            sentinel_event = map_bob_event_to_sentinel(bob_event)
            # Inline detection (same as /v1/events path)
            if engine:
                detection = engine.detect(sentinel_event)
                if detection:
                    try:
                        from sentinel.alert import get_writer
                        get_writer().write(detection)
                    except Exception:
                        pass
            await inserter.put(sentinel_event)
            count += 1
    logger.info("Bob session tail complete: %s events ingested", count)
    return count


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# Module-level singleton — initialized on first use
_inserter: ClickHouseInserter | None = None


async def get_inserter() -> ClickHouseInserter:
    global _inserter
    if _inserter is None:
        _inserter = ClickHouseInserter()
        await _inserter.start()
    return _inserter
