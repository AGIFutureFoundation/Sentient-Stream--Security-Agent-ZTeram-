"""
Omega-Claw — MCP bridge client.

Speaks JSON-RPC 2.0 over subprocess stdio to the hacker-bob MCP server
(Node.js, mcp/server.js). Provides the integration surface between
Omega-Claw's Python orchestrator and hacker-bob's 216-tool offensive runtime.

Usage:
    from omega_claw.mcp_bridge import McpBridge
    bridge = McpBridge.from_default()
    session = bridge.call("bob_init_session", {"target_domain": "example.com"})
    brief = bridge.call("bob_read_assignment_brief", {"session_id": session["session_id"]})
    bridge.close()

See INTEGRATION.md for the full design.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_HACKER_BOB_ROOT = os.environ.get(
    "HACKER_BOB_ROOT",
    str(Path.home() / "hacker-bob"),
)
DEFAULT_MCP_SERVER_PATH = "mcp/server.js"
DEFAULT_AGENTCORE_ENTRYPOINT = "infra/runner/agentcore-entrypoint.py"


class McpBridge:
    """JSON-RPC 2.0 client over a subprocess's stdin/stdout.

    The hacker-bob MCP server (Node.js) reads JSON-RPC requests from stdin
    and writes responses to stdout. This class wraps the framing protocol.

    Thread-safety: the call() method is guarded by a per-instance lock.
    """

    def __init__(
        self,
        server_path: str | Path,
        caller_token: str | None = None,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        timeout_sec: float = 30.0,
    ) -> None:
        self.server_path = str(server_path)
        self.caller_token = caller_token
        self.cwd = str(cwd) if cwd else None
        self.timeout_sec = timeout_sec
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self._next_id = 1
        self._env = {
            "BOB_AGENTCORE": "1",
            "PATH": os.environ.get("PATH", ""),
            "NODE_PATH": os.environ.get("NODE_PATH", ""),
        }
        if caller_token:
            self._env["BOB_MCP_CALLER_TOKEN"] = caller_token
        if env:
            self._env.update(env)

    @classmethod
    def from_default(cls, hacker_bob_root: str | Path | None = None) -> "McpBridge":
        """Construct a bridge using the standard hacker-bob install layout."""
        root = Path(hacker_bob_root or DEFAULT_HACKER_BOB_ROOT)
        if not root.exists():
            raise FileNotFoundError(
                f"hacker-bob not found at {root}. Install with: "
                "`npm install --global hacker-bob@latest` and set HACKER_BOB_ROOT"
            )
        server_path = root / DEFAULT_MCP_SERVER_PATH
        if not server_path.exists():
            raise FileNotFoundError(f"MCP server not found at {server_path}")
        return cls(
            server_path=server_path,
            cwd=str(root),
            caller_token=_mint_caller_token(),
        )

    # --- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._proc is not None:
            return
        self._proc = subprocess.Popen(
            ["node", self.server_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.cwd,
            env=self._env,
            text=True,
            bufsize=1,
        )
        logger.info("MCP bridge started: %s (pid=%s)", self.server_path, self._proc.pid)

    def close(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        except Exception as e:  # noqa: BLE001
            logger.warning("MCP bridge close error: %s", e)
        finally:
            self._proc = None

    def __enter__(self) -> "McpBridge":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # --- JSON-RPC ----------------------------------------------------------

    def call(self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        """Invoke an MCP tool by name. Returns the tool result or raises."""
        if self._proc is None:
            self.start()
        assert self._proc is not None and self._proc.stdin is not None and self._proc.stdout is not None

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": method, "arguments": params or {}},
            "id": self._next_id,
        }
        self._next_id += 1

        timeout = timeout or self.timeout_sec
        with self._lock:
            line = json.dumps(req) + "\n"
            self._proc.stdin.write(line)
            self._proc.stdin.flush()
            # read one JSON object back, handling multi-line if needed
            raw = self._read_json_response(timeout)
        resp = json.loads(raw)
        if "error" in resp:
            err = resp["error"]
            raise McpError(code=err.get("code", -1), message=err.get("message", ""), data=err.get("data"))
        return resp.get("result")

    def _read_json_response(self, timeout: float) -> str:
        """Read one JSON object from stdout. Handles objects spanning lines."""
        assert self._proc is not None and self._proc.stdout is not None
        deadline = time.monotonic() + timeout
        buf: list[str] = []
        depth = 0
        while time.monotonic() < deadline:
            line = self._proc.stdout.readline()
            if not line:
                raise TimeoutError("MCP server closed stdout")
            buf.append(line)
            depth += line.count("{") - line.count("}")
            depth += line.count("[") - line.count("]")
            if depth <= 0 and buf:
                return "".join(buf)
        raise TimeoutError(f"MCP call timed out after {timeout}s")

    # --- convenience wrappers ----------------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        """List all MCP tools registered by the server."""
        result = self.call("tools/list")
        return result.get("tools", []) if isinstance(result, dict) else []

    # --- hacker-bob-specific helpers --------------------------------------

    def init_session(self, target_domain: str, **kwargs: Any) -> dict[str, Any]:
        """Bootstrap a hacker-bob session for a target domain."""
        params = {"target_domain": target_domain, **kwargs}
        return self.call("bob_init_session", params)

    def init_repo_session(self, target_repo: str, **kwargs: Any) -> dict[str, Any]:
        """Bootstrap a hacker-bob OSS-repo session."""
        params = {"target_repo": target_repo, **kwargs}
        return self.call("bob_init_repo_session", params)

    def advance_session(self, session_id: str, to_state: str) -> dict[str, Any]:
        """Drive the 6-state FSM: SETUP → OPEN_FRONTIER → CLAIM_FREEZE → VERIFY → GRADE → REPORT."""
        return self.call("bob_advance_session", {"session_id": session_id, "to_state": to_state})

    def read_session_nucleus(self, session_id: str) -> dict[str, Any]:
        """Read the cryptographically-verified session authority document."""
        return self.call("bob_read_session_nucleus", {"session_id": session_id})

    def read_assignment_brief(self, session_id: str, **kwargs: Any) -> dict[str, Any]:
        """Fetch a single dense brief object for an evaluator (run_context,
        technique_packs, exclusions, intel hints). Replaces string-substituted
        task specs in Omega-Claw."""
        return self.call("bob_read_assignment_brief", {"session_id": session_id, **kwargs})

    def record_candidate_claim(self, session_id: str, claim: dict[str, Any]) -> dict[str, Any]:
        """Stage a finding for verification."""
        return self.call("bob_record_candidate_claim", {"session_id": session_id, "claim": claim})

    def export_security_hub_finding(self, session_id: str, finding_id: str) -> dict[str, Any]:
        """Emit ASFF record + write to S3 Object Lock (WORM)."""
        return self.call("bob_export_security_hub_finding", {
            "session_id": session_id,
            "finding_id": finding_id,
        })

    def query_belief_signals(self, session_id: str, window: int = 10) -> dict[str, Any]:
        """Read the belief-engine residual signal — a novel drift detector
        for agent state. Used by Sentinel Stream's belief_drift rule."""
        return self.call("bob_query_belief_signals", {
            "session_id": session_id,
            "window": window,
        })

    def read_session_events(self, session_id: str) -> list[dict[str, Any]]:
        """Read the session-events.jsonl provenance/audit log as a list of events.
        Consumed by Sentinel Stream's tail_bob_sessions ingester."""
        return self.call("bob_read_session_events", {"session_id": session_id})


class McpError(Exception):
    """JSON-RPC error response from the MCP server."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"MCP error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


def _mint_caller_token() -> str:
    """Mint a 64-hex caller token. In a real deployment, use the
    agentcore-entrypoint.py to mint this — here we generate a random one
    so the bridge is usable without the full bob install."""
    import secrets
    return secrets.token_hex(32)


def health_check() -> dict[str, Any]:
    """Run `hacker-bob doctor --json` to verify install readiness."""
    import shutil
    import json as _json
    bob = shutil.which("hacker-bob")
    if not bob:
        return {"installed": False, "error": "hacker-bob not on PATH. Install with: npm install --global hacker-bob@latest"}
    try:
        result = subprocess.run(
            [bob, "doctor", "--adapter", "generic-mcp", "--json"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return {
            "installed": True,
            "exit_code": result.returncode,
            "stdout": result.stdout[:1000],
            "stderr": result.stderr[:500] if result.stderr else "",
            "parsed": _try_parse(result.stdout),
        }
    except subprocess.TimeoutExpired:
        return {"installed": True, "error": "doctor timed out"}
    except Exception as e:  # noqa: BLE001
        return {"installed": True, "error": str(e)}


def _try_parse(s: str) -> Any:
    try:
        return json.loads(s)
    except Exception:
        return None
