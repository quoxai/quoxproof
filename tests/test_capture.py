import pytest

import quoxproof
from quoxproof.verify import verify_chain


@pytest.fixture
def store_root(tmp_path):
    quoxproof.configure(agent_id="agent-test", store_root=str(tmp_path), session_id="cap-sess")
    return tmp_path


def test_decorator_records_and_chain_verifies(store_root):
    @quoxproof.tool
    def add(a, b):
        return a + b

    assert add(2, 3) == 5
    assert add(10, 1) == 11

    refs = quoxproof.get_reference_ids()
    assert len(refs) == 2
    assert refs[0]["tool_name"] == "add"

    receipts = quoxproof.capture._active().store.load_session("cap-sess")
    assert len(receipts) == 2
    result = verify_chain(receipts)
    assert result["status"] == "INTACT"
    assert result["signatures_verified"] == 2


def test_error_path_records_status_error_and_reraises(store_root):
    @quoxproof.tool
    def boom():
        raise ValueError("nope")

    with pytest.raises(ValueError):
        boom()

    receipts = quoxproof.capture._active().store.load_session("cap-sess")
    assert receipts[-1]["status"] == "error"
    assert receipts[-1]["error"]["type"] == "ValueError"
    assert receipts[-1]["error"]["message"] == "nope"
    # even an error receipt is signed and chains
    assert verify_chain(receipts)["status"] == "INTACT"


def test_signature_unchanged_transparent(store_root):
    @quoxproof.tool(name="renamed", visibility="public")
    def greet(name):
        return f"hi {name}"

    assert greet("arun") == "hi arun"
    receipts = quoxproof.capture._active().store.load_session("cap-sess")
    assert receipts[-1]["tool_name"] == "renamed"
    assert receipts[-1]["visibility"] == "public"
    assert receipts[-1]["output"] == "hi arun"


def test_session_head_resumes_across_recorders(tmp_path):
    quoxproof.configure(store_root=str(tmp_path), session_id="resume")

    @quoxproof.tool
    def f(x):
        return x

    f(1)
    f(2)
    # new recorder, same session file: seq must continue at 3, chain still intact
    quoxproof.configure(store_root=str(tmp_path), session_id="resume")

    @quoxproof.tool
    def g(x):
        return x

    g(3)
    receipts = quoxproof.capture._active().store.load_session("resume")
    assert [r["seq"] for r in receipts] == [1, 2, 3]
    assert verify_chain(receipts)["status"] == "INTACT"


def test_flush_and_health(store_root):
    assert quoxproof.is_healthy() is True
    assert quoxproof.flush() == len(quoxproof.get_reference_ids())
