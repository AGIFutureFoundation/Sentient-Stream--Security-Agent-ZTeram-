"""
Sentinel Stream SDK — drop-in Python instrumentation for any LLM app.

Usage:
    from sentinel_sdk import track, track_prompt, track_tool_call, track_response

    track_prompt(agent_id="my-agent", payload=user_message, user_id="u123")
    track_tool_call(agent_id="my-agent", tool="filesystem.read", args={"path": "/etc/passwd"})
    track_response(agent_id="my-agent", payload=model_output)

Or as a decorator:
    from sentinel_sdk import instrument_agent

    @instrument_agent(agent_id="research-bot")
    def my_agent_handler(prompt: str) -> str:
        # ... LLM call ...
        return response

Or as a context manager:
    from sentinel_sdk import agent_session

    with agent_session(agent_id="research-bot", user_id="u123") as session:
        session.prompt("What's the weather?")
        session.tool_call("http.get", {"url": "..."})
        session.response("Sunny, 72F")
"""
from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

import httpx

logger = logging.getLogger(__name__)

SENTINEL_API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:8000")
SENTINEL_APP_ID = os.environ.get("SENTINEL_APP_ID", "default")
SENTINEL_ENABLED = os.environ.get("SENTINEL_ENABLED", "1") != "0"
SENTINEL_BATCH_SIZE = int(os.environ.get("SENTINEL_BATCH_SIZE", "100"))
SENTINEL_FLUSH_INTERVAL_SEC = float(os.environ.get("SENTINEL_FLUSH_INTERVAL_SEC", "1.0"))


# --- Internal batcher ------------------------------------------------------

class _Batcher:
    """Thread-safe batch sender. Flushes every interval or when batch fills."""

    _instance: "_Batcher | None" = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._lock_inner = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._thread.start()

    @classmethod
    def get(cls) -> "_Batcher":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def put(self, event: dict[str, Any]) -> None:
        if not SENTINEL_ENABLED:
            return
        with self._lock_inner:
            self._events.append(event)
            if len(self._events) >= SENTINEL_BATCH_SIZE:
                self._flush()

    def _flush_loop(self) -> None:
        while not self._stop.wait(SENTINEL_FLUSH_INTERVAL_SEC):
            try:
                self._flush()
            except Exception as e:  # noqa: BLE001
                logger.debug("SDK flush error: %s", e)

    def _flush(self) -> None:
        with self._lock_inner:
            if not self._events:
                return
            batch, self._events = self._events, []
        try:
            resp = httpx.post(
                f"{SENTINEL_API_URL}/v1/events",
                json={"events": batch},
                timeout=5,
            )
            if resp.status_code != 202:
                logger.debug("SDK ingest returned %s", resp.status_code)
        except httpx.HTTPError as e:
            logger.debug("SDK ingest failed: %s", e)

    def stop(self) -> None:
        self._stop.set()
        self._flush()
        self._thread.join(timeout=2)


# --- Public API ------------------------------------------------------------

def track(
    agent_id: str,
    event_type: str,
    payload: str = "",
    tool_name: str = "",
    tokens_in: int = 0,
    tokens_out: int = 0,
    user_id: str = "",
    session_id: str = "",
    risk_score: float = 0.0,
    flags: list[str] | None = None,
    app_id: str = "",
) -> None:
    """Track a single LLM agent event. Fire-and-forget; batched internally.

    Args:
        agent_id: unique agent identifier (e.g. "research-bot")
        event_type: one of "prompt", "tool_call", "tool_response",
                    "model_response", "retrieval", "action"
        payload: the event payload (prompt text, tool args, model output, etc.)
        tool_name: tool name (for tool_call/tool_response events)
        tokens_in: input tokens (for prompt/model_response events)
        tokens_out: output tokens (for model_response events)
        user_id: end-user identifier
        session_id: session identifier
        risk_score: 0.0-1.0 client-side risk hint
        flags: list of client-side flags (e.g. ["untrusted_input"])
        app_id: application identifier (defaults to env SENTINEL_APP_ID)
    """
    event = {
        "id": _hash_event(agent_id, event_type, payload),
        "ts": _now_iso(),
        "agent_id": agent_id,
        "app_id": app_id or SENTINEL_APP_ID,
        "event_type": event_type,
        "tool_name": tool_name,
        "payload": payload,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "user_id": user_id,
        "session_id": session_id,
        "risk_score": risk_score,
        "flags": flags or [],
    }
    _Batcher.get().put(event)


def track_prompt(agent_id: str, payload: str, **kwargs: Any) -> None:
    """Convenience wrapper for track(..., event_type='prompt')."""
    track(agent_id, "prompt", payload=payload, **kwargs)


def track_tool_call(agent_id: str, tool: str, args: dict[str, Any] | str = "", **kwargs: Any) -> None:
    """Convenience wrapper for track(..., event_type='tool_call')."""
    payload = args if isinstance(args, str) else json.dumps(args, default=str)
    track(agent_id, "tool_call", payload=payload, tool_name=tool, **kwargs)


def track_tool_response(agent_id: str, tool: str, result: Any, **kwargs: Any) -> None:
    """Convenience wrapper for track(..., event_type='tool_response')."""
    payload = result if isinstance(result, str) else json.dumps(result, default=str)
    track(agent_id, "tool_response", payload=payload, tool_name=tool, **kwargs)


def track_response(agent_id: str, payload: str, tokens_in: int = 0, tokens_out: int = 0, **kwargs: Any) -> None:
    """Convenience wrapper for track(..., event_type='model_response')."""
    track(agent_id, "model_response", payload=payload, tokens_in=tokens_in, tokens_out=tokens_out, **kwargs)


def track_retrieval(agent_id: str, query: str, results: Any, **kwargs: Any) -> None:
    """Convenience wrapper for track(..., event_type='retrieval')."""
    payload = json.dumps({"query": query, "results_preview": str(results)[:500]}, default=str)
    track(agent_id, "retrieval", payload=payload, **kwargs)


# --- Decorator API ---------------------------------------------------------

def instrument_agent(agent_id: str, **default_kwargs: Any) -> Callable:
    """Decorator that auto-tracks prompt (input) + model_response (output).

    Usage:
        @instrument_agent(agent_id="research-bot")
        def my_agent_handler(prompt: str) -> str:
            return llm.complete(prompt)

    The decorator records:
      - a 'prompt' event with the input string
      - a 'model_response' event with the return value
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            input_str = args[0] if args else json.dumps(kwargs, default=str)
            track_prompt(agent_id, str(input_str)[:10000], **default_kwargs)
            t0 = time.perf_counter()
            try:
                result = fn(*args, **kwargs)
                elapsed_ms = (time.perf_counter() - t0) * 1000
                track_response(
                    agent_id,
                    str(result)[:10000],
                    **{**default_kwargs, "flags": ["ok"]},
                )
                return result
            except Exception as e:
                track(
                    agent_id, "action",
                    payload=f"exception: {type(e).__name__}: {e}",
                    flags=["error"],
                    **default_kwargs,
                )
                raise
        return wrapper
    return decorator


# --- Context manager API ----------------------------------------------------

@dataclass
class AgentSession:
    """Context manager that tracks a multi-turn agent session.

    Usage:
        with agent_session(agent_id="support-bot", user_id="u123") as s:
            s.prompt("What's the return policy?")
            s.tool_call("search.query", {"q": "return policy"})
            s.response("You can return within 30 days...")
    """
    agent_id: str
    user_id: str = ""
    session_id: str = field(default_factory=lambda: _random_id())
    app_id: str = ""

    def prompt(self, payload: str, **kwargs: Any) -> None:
        track_prompt(self.agent_id, payload, user_id=self.user_id,
                     session_id=self.session_id, app_id=self.app_id, **kwargs)

    def tool_call(self, tool: str, args: dict[str, Any] | str = "", **kwargs: Any) -> None:
        track_tool_call(self.agent_id, tool, args, user_id=self.user_id,
                        session_id=self.session_id, app_id=self.app_id, **kwargs)

    def tool_response(self, tool: str, result: Any, **kwargs: Any) -> None:
        track_tool_response(self.agent_id, tool, result, user_id=self.user_id,
                            session_id=self.session_id, app_id=self.app_id, **kwargs)

    def response(self, payload: str, tokens_in: int = 0, tokens_out: int = 0, **kwargs: Any) -> None:
        track_response(self.agent_id, payload, tokens_in=tokens_in, tokens_out=tokens_out,
                       user_id=self.user_id, session_id=self.session_id,
                       app_id=self.app_id, **kwargs)

    def retrieval(self, query: str, results: Any, **kwargs: Any) -> None:
        track_retrieval(self.agent_id, query, results, user_id=self.user_id,
                        session_id=self.session_id, app_id=self.app_id, **kwargs)

    def __enter__(self) -> "AgentSession":
        track(self.agent_id, "action", payload="session_start",
              user_id=self.user_id, session_id=self.session_id, app_id=self.app_id,
              flags=["session_start"])
        return self

    def __exit__(self, *exc: Any) -> None:
        track(self.agent_id, "action", payload="session_end",
              user_id=self.user_id, session_id=self.session_id, app_id=self.app_id,
              flags=["session_end"])


@contextmanager
def agent_session(agent_id: str, user_id: str = "", session_id: str = "", app_id: str = "") -> Iterator[AgentSession]:
    """Context manager factory for AgentSession."""
    s = AgentSession(agent_id=agent_id, user_id=user_id, session_id=session_id, app_id=app_id)
    yield s.__enter__()
    s.__exit__(None, None, None)


# --- Helpers ---------------------------------------------------------------

def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _hash_event(agent_id: str, event_type: str, payload: str) -> str:
    raw = f"{_now_iso()}{agent_id}{event_type}{payload[:200]}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _random_id() -> str:
    import secrets
    return secrets.token_hex(12)


def shutdown() -> None:
    """Flush all pending events and stop the background sender. Call on app shutdown."""
    _Batcher.get().stop()


__all__ = [
    "track",
    "track_prompt",
    "track_tool_call",
    "track_tool_response",
    "track_response",
    "track_retrieval",
    "instrument_agent",
    "agent_session",
    "AgentSession",
    "shutdown",
]
