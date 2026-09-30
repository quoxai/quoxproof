"""QUOXTRUST F11 (engagement c4, FND_01M3R8JM243HJQ7FTE193HJQ7F) —
a receipt-write failure must not mask the tool outcome, must be accounted, and
must not corrupt the hash chain (the quoxflow-B4 accounting class).

Before the fix: the @tool wrapper called record_call in a `finally`, so a
store.append failure REPLACED the tool's return value (a successful outcome
masked by the write error); and record_call advanced _seq/_prev_hash BEFORE the
append, so a failed write left the chain head pointing at a receipt that was
never persisted — corrupting the next receipt's linkage.
"""
import quoxproof.capture as cap
from quoxproof.capture import tool, configure, _active
from quoxproof.verify import verify_chain


def _boom(*_a, **_k):
    raise OSError("disk full")


def test_write_failure_does_not_mask_successful_tool_output(tmp_path):
    configure(store_root=str(tmp_path))
    rec = _active()

    @tool
    def add(a, b):
        return a + b

    orig = rec.store.append
    rec.store.append = _boom
    try:
        result = add(2, 3)  # the tool SUCCEEDED; a write failure must not hijack this
    finally:
        rec.store.append = orig

    assert result == 5, "a receipt-write failure must not mask/replace the successful tool output"
    assert rec.write_failures >= 1, "the write failure must be ACCOUNTED (counter), never silent"


def test_write_failure_reraises_the_tools_own_exception_not_the_write_error(tmp_path):
    configure(store_root=str(tmp_path))
    rec = _active()

    @tool
    def boom_tool():
        raise ValueError("tool failed for its own reason")

    orig = rec.store.append
    rec.store.append = _boom
    try:
        raised = None
        try:
            boom_tool()
        except Exception as exc:
            raised = exc
    finally:
        rec.store.append = orig

    assert isinstance(raised, ValueError), "the tool's own exception must surface, not the receipt-write OSError"
    assert rec.write_failures >= 1


def test_chain_is_not_corrupted_by_a_write_failure(tmp_path):
    configure(store_root=str(tmp_path))
    rec = _active()

    @tool
    def t():
        return "ok"

    seq_before = rec._seq
    orig = rec.store.append
    rec.store.append = _boom
    try:
        t()  # write fails — must not advance the chain head
    finally:
        rec.store.append = orig

    assert rec._seq == seq_before, "a failed append must not advance _seq (no phantom chain slot)"

    # Recovery: the next successful call chains cleanly and the persisted chain verifies.
    t()
    receipts = rec.store.load_session(rec.session_id)
    assert len(receipts) == 1
    assert verify_chain(receipts)["status"] == "INTACT"
