"""Model Context Protocol (MCP) auto-hook.

Patches the MCP server's ``call_tool`` dispatch so every MCP tool execution
produces a signed receipt. This mirrors the interception seam already used in
quoxmcp (``quoxmcp/lib/tool-adapter.js``), which wraps every ``server.tool`` and
sees name/input/timing/error/result. Mirrors AEVS's ``pip install aevs[mcp]``.
No-op if ``mcp`` is not installed.

Handles both MCP SDK generations: v1's ``mcp.server.fastmcp.FastMCP`` and v2's
``mcp.server.mcpserver.MCPServer`` (FastMCP was renamed in 2.x). ``call_tool`` is
async in both, so the wrapper is async and awaits the original.

Status: wired against the real ``call_tool`` dispatch point; driven end to end in
tests/test_adapters.py with an installed mcp package.
"""

from __future__ import annotations

import time
from typing import Any

_original_call_tool = None
_patched_class = None


def _resolve_server_class():
    # v2 first (current), then v1 fallback.
    try:
        from mcp.server.mcpserver import MCPServer

        return MCPServer
    except Exception:
        pass
    try:
        from mcp.server.fastmcp import FastMCP

        return FastMCP
    except Exception:
        return None


def patch(recorder) -> bool:
    global _original_call_tool, _patched_class
    ServerClass = _resolve_server_class()
    if ServerClass is None:
        return False
    if _original_call_tool is not None:
        return True

    _patched_class = ServerClass
    _original_call_tool = ServerClass.call_tool

    async def call_tool(self, name: str, arguments: dict, *args: Any, **kwargs: Any):  # type: ignore[no-redef]
        start = time.perf_counter()
        status = "ok"
        error = None
        output = None
        try:
            output = await _original_call_tool(self, name, arguments, *args, **kwargs)
            return output
        except Exception as exc:  # noqa: BLE001
            status = "error"
            error = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            duration_ms = int((time.perf_counter() - start) * 1000)
            recorder.record_call(
                tool_name=name,
                inputs={"arguments": arguments},
                output=output,
                status=status,
                error=error,
                duration_ms=duration_ms,
                framework="mcp",
            )

    ServerClass.call_tool = call_tool  # type: ignore[assignment]
    return True


def unpatch() -> None:
    global _original_call_tool, _patched_class
    if _original_call_tool is None or _patched_class is None:
        return
    _patched_class.call_tool = _original_call_tool  # type: ignore[assignment]
    _original_call_tool = None
    _patched_class = None
