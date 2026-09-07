"""Drive the LangChain and MCP auto-hooks against the REAL installed frameworks.

These prove the "just as easy as AEVS" claim: enable(), use your tools normally,
get signed receipts. Skipped (not silently passed) when a framework is absent.
"""

import asyncio

import pytest

import quoxproof
from quoxproof.verify import verify_chain

langchain_core = pytest.importorskip("langchain_core")


@pytest.fixture
def fresh(tmp_path):
    quoxproof.configure(store_root=str(tmp_path), session_id="adapters")
    yield
    quoxproof.disable()


def test_langchain_auto_hook_records_and_verifies(fresh):
    from langchain_core.tools import tool as lc_tool

    @lc_tool
    def multiply(a: int, b: int) -> int:
        """Multiply two integers."""
        return a * b

    patched = quoxproof.enable()
    assert "langchain" in patched

    assert multiply.invoke({"a": 6, "b": 7}) == 42

    receipts = quoxproof.capture._active().store.load_session("adapters")
    assert len(receipts) == 1
    assert receipts[0]["tool_name"] == "multiply"
    assert receipts[0]["status"] == "ok"
    assert verify_chain(receipts)["status"] == "INTACT"


def test_mcp_auto_hook_records_and_verifies(fresh):
    pytest.importorskip("mcp")
    from quoxproof.adapters.mcp import _resolve_server_class

    ServerClass = _resolve_server_class()
    if ServerClass is None:
        pytest.skip("no MCP server class resolvable")

    server = ServerClass("test-server")

    @server.tool()
    def add(a: int, b: int) -> int:
        """Add two integers."""
        return a + b

    patched = quoxproof.enable()
    assert "mcp" in patched

    async def drive():
        return await server.call_tool("add", {"a": 2, "b": 3})

    asyncio.run(drive())

    receipts = quoxproof.capture._active().store.load_session("adapters")
    assert len(receipts) == 1
    assert receipts[0]["tool_name"] == "add"
    assert verify_chain(receipts)["status"] == "INTACT"
