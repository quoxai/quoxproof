"""LangChain / LangGraph auto-hook.

Patches ``langchain_core.tools.BaseTool.run`` so every tool invocation through
the standard dispatch produces a signed receipt, with no change to tool code.
Mirrors AEVS's ``pip install aevs[langchain]`` behaviour. No-op if
``langchain_core`` is not installed.

Status: wired against the real BaseTool.run dispatch point; driven end to end in
tests/test_adapters.py with an installed langchain-core.
"""

from __future__ import annotations

import time
from typing import Any

_original_run = None


def patch(recorder) -> bool:
    global _original_run
    try:
        from langchain_core.tools import BaseTool
    except Exception:
        return False
    if _original_run is not None:
        return True  # already patched

    _original_run = BaseTool.run

    def run(self, tool_input: Any = None, *args: Any, **kwargs: Any):  # type: ignore[no-redef]
        start = time.perf_counter()
        status = "ok"
        error = None
        output = None
        try:
            output = _original_run(self, tool_input, *args, **kwargs)
            return output
        except Exception as exc:  # noqa: BLE001
            status = "error"
            error = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            duration_ms = int((time.perf_counter() - start) * 1000)
            recorder.record_call(
                tool_name=getattr(self, "name", type(self).__name__),
                inputs={"tool_input": tool_input, "kwargs": dict(kwargs)},
                output=output,
                status=status,
                error=error,
                duration_ms=duration_ms,
                framework="langchain",
            )

    BaseTool.run = run  # type: ignore[assignment]
    return True


def unpatch() -> None:
    global _original_run
    if _original_run is None:
        return
    try:
        from langchain_core.tools import BaseTool

        BaseTool.run = _original_run  # type: ignore[assignment]
    except Exception:
        pass
    _original_run = None
