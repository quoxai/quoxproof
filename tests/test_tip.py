import quoxproof
from quoxproof.chain import GENESIS_PREV_HASH
from quoxproof.crypto import generate_keypair
from quoxproof.receipt import build_receipt
from quoxproof.tip import build_tip, verify_tip
from quoxproof.verify import verify_chain


def _chain(kp, n=3):
    receipts, prev = [], GENESIS_PREV_HASH
    for i in range(1, n + 1):
        r = build_receipt(keypair=kp, seq=i, prev_hash=prev, session_id="s",
                          tool_name=f"t{i}", inputs={"a": i}, output=i, status="ok",
                          error=None, duration_ms=1)
        prev = r["receipt_hash"]
        receipts.append(r)
    return receipts


def test_tip_matches_intact_chain():
    kp = generate_keypair()
    chain = _chain(kp, 3)
    tip = build_tip(kp, "s", chain)
    res = verify_tip(tip, chain)
    assert res["matches"] is True
    assert res["sig_valid"] is True
    assert res["tip_seq"] == 3


def test_tip_detects_truncation():
    kp = generate_keypair()
    chain = _chain(kp, 3)
    tip = build_tip(kp, "s", chain)
    # drop the last receipt: chain is now truncated behind the checkpoint
    res = verify_tip(tip, chain[:-1])
    assert res["matches"] is False
    assert res["reason"] == "chain_head_does_not_match_checkpoint"


def test_tip_forged_sig_fails():
    kp = generate_keypair()
    other = generate_keypair()
    chain = _chain(kp, 2)
    tip = build_tip(kp, "s", chain)
    from quoxproof.crypto import sign_hash
    tip["sig"]["signature"] = sign_hash(tip["tip_chain_hash"], other.private_key)
    res = verify_tip(tip, chain)
    assert res["sig_valid"] is False


def test_verify_chain_reports_checkpoint_rung():
    kp = generate_keypair()
    chain = _chain(kp, 3)
    # no tip: rung unavailable, honest reason
    res = verify_chain(chain)
    assert res["trust_ladder"]["checkpoint"]["available"] is False
    # with tip: rung available and matches
    tip = build_tip(kp, "s", chain)
    res2 = verify_chain(chain, tip=tip)
    assert res2["trust_ladder"]["checkpoint"]["matches"] is True


def test_checkpoint_module_helper_writes_tip(tmp_path):
    quoxproof.configure(store_root=str(tmp_path), session_id="cp")

    @quoxproof.tool
    def f(x):
        return x

    f(1); f(2)
    tip = quoxproof.checkpoint()
    assert tip["tip_seq"] == 2
    assert quoxproof.capture._active().store.tip_path("cp").exists()
    receipts = quoxproof.capture._active().store.load_session("cp")
    assert verify_chain(receipts, tip=tip)["trust_ladder"]["checkpoint"]["matches"] is True
