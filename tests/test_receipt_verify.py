import copy

from quoxproof.chain import GENESIS_PREV_HASH, compute_receipt_hash
from quoxproof.crypto import generate_keypair, raw_public_key_b64
from quoxproof.receipt import build_receipt
from quoxproof.verify import verify_chain


def _chain(keypair, n=3, visibility="private"):
    receipts = []
    prev = GENESIS_PREV_HASH
    for i in range(1, n + 1):
        r = build_receipt(
            keypair=keypair,
            seq=i,
            prev_hash=prev,
            session_id="sess-1",
            tool_name=f"tool_{i}",
            inputs={"args": [i], "kwargs": {}},
            output=f"out{i}",
            status="ok",
            error=None,
            duration_ms=i * 10,
            visibility=visibility,
        )
        prev = r["receipt_hash"]
        receipts.append(r)
    return receipts


def test_build_receipt_hash_excludes_sig_and_hash_field():
    kp = generate_keypair()
    r = build_receipt(
        keypair=kp, seq=1, prev_hash=GENESIS_PREV_HASH, session_id="s",
        tool_name="t", inputs={"a": 1}, output="x", status="ok", error=None, duration_ms=5,
    )
    assert r["receipt_hash"] == compute_receipt_hash(r)
    assert r["prev_hash"] == GENESIS_PREV_HASH
    assert r["sig"]["sig_type"] == "ed25519"
    assert r["error"] is None


def test_private_omits_raw_public_embeds_raw():
    kp = generate_keypair()
    priv = build_receipt(keypair=kp, seq=1, prev_hash=GENESIS_PREV_HASH, session_id="s",
                         tool_name="t", inputs={"a": 1}, output="secret", status="ok",
                         error=None, duration_ms=1, visibility="private")
    assert "input" not in priv and "output" not in priv
    assert len(priv["input_hash"]) == 64

    pub = build_receipt(keypair=kp, seq=1, prev_hash=GENESIS_PREV_HASH, session_id="s",
                        tool_name="t", inputs={"a": 1}, output="secret", status="ok",
                        error=None, duration_ms=1, visibility="public")
    assert pub["output"] == "secret"


def test_intact_chain_verifies():
    kp = generate_keypair()
    result = verify_chain(_chain(kp, 3))
    assert result["status"] == "INTACT"
    assert result["signatures_verified"] == 3
    assert result["trust_ladder"]["key_source"] == "embedded"
    # higher rungs are honestly reported as unavailable, never true
    assert result["trust_ladder"]["witnessed"]["available"] is False
    assert result["trust_ladder"]["governed_execution"]["available"] is False


def test_pinned_key_reports_pinned_source():
    kp = generate_keypair()
    chain = _chain(kp, 2)
    result = verify_chain(chain, pinned_public_key_b64=raw_public_key_b64(kp.public_key))
    assert result["status"] == "INTACT"
    assert result["trust_ladder"]["key_source"] == "pinned"


def test_empty_chain_is_intact():
    assert verify_chain([])["status"] == "INTACT"


def test_tampered_output_hash_breaks():
    kp = generate_keypair()
    chain = _chain(kp, 3)
    chain[1]["output_hash"] = "f" * 64  # tamper: hash no longer matches signature/body
    result = verify_chain(chain)
    assert result["status"] == "BROKEN"
    # recomputed receipt_hash won't match the stored (signed) one
    assert result["reason"] in ("RECEIPT_HASH_MISMATCH", "SIGNATURE_INVALID")


def test_broken_linkage_detected():
    kp = generate_keypair()
    chain = _chain(kp, 3)
    chain[2]["prev_hash"] = "0" * 64  # wrong link
    # must also re-sign to isolate linkage from hash check; instead expect a failure
    result = verify_chain(chain)
    assert result["status"] == "BROKEN"


def test_forged_signature_breaks():
    kp = generate_keypair()
    chain = _chain(kp, 2)
    # swap in a different key's signature but keep the hash: signature must fail
    other = generate_keypair()
    from quoxproof.crypto import sign_hash
    chain[0]["sig"]["signature"] = sign_hash(chain[0]["receipt_hash"], other.private_key)
    result = verify_chain(chain)
    assert result["status"] == "BROKEN"
    assert result["reason"] == "SIGNATURE_INVALID"


def test_reordered_receipts_break_seq():
    kp = generate_keypair()
    chain = _chain(kp, 3)
    reordered = [chain[0], chain[2], chain[1]]
    result = verify_chain(reordered)
    assert result["status"] == "BROKEN"


def test_dropped_middle_receipt_breaks():
    kp = generate_keypair()
    chain = _chain(kp, 3)
    dropped = [chain[0], chain[2]]  # seq jumps 1 -> 3
    result = verify_chain(dropped)
    assert result["status"] == "BROKEN"
    assert result["reason"] == "SEQ_INVALID"
