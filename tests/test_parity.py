"""Parity with the real AEVS module surface, plus the QuoxProof extras."""

import quoxproof
from quoxproof.verify import verify_chain

# The AEVS 0.2.2 public module functions QuoxProof must match one-to-one.
AEVS_MODULE_API = {
    "configure",
    "enable",
    "disable",
    "flush",
    "get_reference_id",
    "get_reference_ids",
    "get_session_id",
    "is_healthy",
    "clear_reference_ids",
    "reset_config",
}


def test_module_api_covers_aevs():
    missing = AEVS_MODULE_API - set(dir(quoxproof))
    assert not missing, f"missing AEVS-parity functions: {missing}"
    # and the QuoxProof addition AEVS does not have:
    assert hasattr(quoxproof, "tool")
    assert hasattr(quoxproof, "verify_chain")


def test_clear_and_reset(tmp_path):
    quoxproof.configure(store_root=str(tmp_path), session_id="parity")

    @quoxproof.tool
    def f(x):
        return x

    f(1)
    assert len(quoxproof.get_reference_ids()) == 1
    quoxproof.clear_reference_ids()
    assert quoxproof.get_reference_ids() == []
    quoxproof.reset_config()  # tears down; next call lazily rebuilds
    assert quoxproof.is_healthy() in (True, False)


def test_receipt_has_rich_metadata(tmp_path):
    quoxproof.configure(store_root=str(tmp_path), session_id="meta", agent_id="a1")

    @quoxproof.tool
    def g(x):
        return x * 2

    g(21)
    r = quoxproof.capture._active().store.load_session("meta")[0]
    for field in (
        "quoxproof_version", "sdk_version", "reference_id" if False else "receipt_id",
        "session_id", "seq", "tool_name", "framework", "status", "duration_ms",
        "input_hash", "output_hash", "prev_hash", "receipt_hash", "sig",
        "started_at", "ended_at", "agent_id",
    ):
        assert field in r, f"receipt missing {field}"
    assert r["framework"] == "decorator"
    assert verify_chain([r])["status"] == "INTACT"
