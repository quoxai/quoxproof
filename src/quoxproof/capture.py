"""The capture layer: a transparent decorator and the module-level API.

Ergonomics deliberately match AEVS one-to-one, so a team already using
``aevs.configure()`` / ``aevs.enable()`` / a tool decorator can switch imports and
keep going. Where AEVS then POSTs HMAC-signed receipts to its backend, QuoxProof
signs Ed25519 and writes offline-verifiable receipts to the local store.

Unlike AEE's ``wrap`` (which injects a context object as the first argument),
``@quoxproof.tool`` is transparent: the wrapped function's signature is
unchanged, matching AEVS's "zero changes to your tools".
"""

from __future__ import annotations

import functools
import threading
import time
import uuid
from typing import Any, Callable

from .receipt import build_receipt, now_iso, reference_id_of
from .store import ProofStore


class Recorder:
    """Holds the signing key, the running chain head, and captured references."""

    def __init__(
        self,
        agent_id: str | None = None,
        visibility: str = "private",
        store_root: str | None = None,
        session_id: str | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.visibility = visibility
        self.store = ProofStore(store_root)
        self.session_id = session_id or str(uuid.uuid4())
        self._lock = threading.Lock()
        seq, prev = self.store.head(self.session_id)
        self._seq = seq
        self._prev_hash = prev
        self._references: list[dict] = []

    def record_call(
        self,
        tool_name: str,
        inputs: Any,
        output: Any,
        status: str,
        error: dict | None,
        duration_ms: int,
        tool_call_id: str | None = None,
        visibility: str | None = None,
        framework: str = "direct",
        started_at: str | None = None,
        ended_at: str | None = None,
    ) -> dict:
        """Build, sign, persist one receipt; return it."""
        with self._lock:
            self._seq += 1
            seq = self._seq
            prev = self._prev_hash
            receipt = build_receipt(
                keypair=self.store.keypair,
                seq=seq,
                prev_hash=prev,
                session_id=self.session_id,
                tool_name=tool_name,
                inputs=inputs,
                output=output,
                status=status,
                error=error,
                duration_ms=duration_ms,
                agent_id=self.agent_id,
                tool_call_id=tool_call_id,
                visibility=visibility or self.visibility,
                framework=framework,
                started_at=started_at,
                ended_at=ended_at,
            )
            self._prev_hash = receipt["receipt_hash"]
            self.store.append(self.session_id, receipt)
            self._references.append(
                {
                    "seq": seq,
                    "tool_name": tool_name,
                    "tool_call_id": tool_call_id,
                    "reference_id": reference_id_of(receipt),
                    "receipt_hash": receipt["receipt_hash"],
                }
            )
            return receipt

    def reference_ids(self, clear: bool = False) -> list[dict]:
        with self._lock:
            out = list(self._references)
            if clear:
                self._references = []
            return out

    def clear(self) -> None:
        with self._lock:
            self._references = []


# ---------------------------------------------------------------------------
# Module-level singleton API (AEVS parity).
# ---------------------------------------------------------------------------

_recorder: Recorder | None = None
_recorder_lock = threading.Lock()
_enabled = False
_patched: list[str] = []


def configure(
    agent_id: str | None = None,
    visibility: str = "private",
    store_root: str | None = None,
    session_id: str | None = None,
) -> None:
    """Create (or replace) the active recorder. No API key: local-first."""
    global _recorder
    with _recorder_lock:
        _recorder = Recorder(
            agent_id=agent_id,
            visibility=visibility,
            store_root=store_root,
            session_id=session_id,
        )


def _active() -> Recorder:
    global _recorder
    if _recorder is None:
        with _recorder_lock:
            if _recorder is None:
                _recorder = Recorder()
    return _recorder


def enable() -> list[str]:
    """Auto-hook installed frameworks (LangChain, MCP). Returns patched names.

    Best-effort: a framework that is not installed is skipped silently, exactly
    like AEVS's optional extras. The ``@tool`` decorator works with or without
    this call.
    """
    global _enabled, _patched
    _active()
    patched: list[str] = []
    try:
        from .adapters import langchain as _lc

        if _lc.patch(_active()):
            patched.append("langchain")
    except Exception:
        pass
    try:
        from .adapters import mcp as _mcp

        if _mcp.patch(_active()):
            patched.append("mcp")
    except Exception:
        pass
    _patched = patched
    _enabled = True
    return patched


def disable() -> None:
    """Undo framework patching. The recorder and its receipts remain."""
    global _enabled, _patched
    try:
        from .adapters import langchain as _lc

        _lc.unpatch()
    except Exception:
        pass
    try:
        from .adapters import mcp as _mcp

        _mcp.unpatch()
    except Exception:
        pass
    _patched = []
    _enabled = False


def tool(fn: Callable | None = None, *, name: str | None = None, visibility: str | None = None):
    """Transparent decorator: sign a receipt for every call. Signature unchanged.

    Usable as ``@tool``, ``@tool()``, or ``@tool(name="...", visibility="public")``.
    """

    def deco(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            started_at = now_iso()
            start = time.perf_counter()
            status = "ok"
            error: dict | None = None
            output: Any = None
            try:
                output = f(*args, **kwargs)
                return output
            except Exception as exc:  # noqa: BLE001 - re-raised after recording
                status = "error"
                error = {"type": type(exc).__name__, "message": str(exc)}
                raise
            finally:
                duration_ms = int((time.perf_counter() - start) * 1000)
                _active().record_call(
                    tool_name=name or getattr(f, "__name__", "anonymous"),
                    inputs={"args": list(args), "kwargs": dict(kwargs)},
                    output=output,
                    status=status,
                    error=error,
                    duration_ms=duration_ms,
                    visibility=visibility,
                    framework="decorator",
                    started_at=started_at,
                    ended_at=now_iso(),
                )

        return wrapper

    if callable(fn):
        return deco(fn)
    return deco


def clear_reference_ids() -> None:
    """Drop the captured reference-id list (AEVS parity). Receipts on disk stay."""
    _active().clear()


def reset_config() -> None:
    """Tear down the active recorder (AEVS parity). A fresh one is lazily created."""
    global _recorder, _enabled
    disable()
    with _recorder_lock:
        _recorder = None
    _enabled = False


def checkpoint() -> dict:
    """Sign a checkpoint over the current session's chain head and store it.

    Returns the tip dict. Publish or pin the tip out of band to make later
    tail-rewrite or truncation detectable.
    """
    from .tip import build_tip

    rec = _active()
    receipts = rec.store.load_session(rec.session_id)
    tip = build_tip(rec.store.keypair, rec.session_id, receipts)
    rec.store.write_tip(rec.session_id, tip)
    return tip


def get_session_id() -> str:
    return _active().session_id


def get_reference_ids(clear: bool = False) -> list[dict]:
    return _active().reference_ids(clear=clear)


def get_reference_id(seq_or_tool_call_id: int | str) -> dict | None:
    for ref in _active().reference_ids():
        if ref["seq"] == seq_or_tool_call_id or ref["tool_call_id"] == seq_or_tool_call_id:
            return ref
    return None


def flush() -> int:
    """Receipts are written synchronously, so this is a no-op that reports count.

    Honest by design: there is no hidden background drainer to wait on. Returns
    the number of receipts recorded so far this session.
    """
    return len(_active().reference_ids())


def is_healthy() -> bool:
    """True if the store root exists and is writable (the local buffer is healthy)."""
    import os as _os

    try:
        root = _active().store.root
        return root.exists() and _os.access(root, _os.W_OK)
    except Exception:
        return False
