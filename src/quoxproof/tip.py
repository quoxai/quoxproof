"""Signed checkpoints over a receipt chain (a QuoxProof tip, WARD-tip shaped).

A checkpoint pins the chain head: it signs the head receipt's ``receipt_hash``
plus the entry count, so a checkpoint published or stored out of band lets a
verifier detect tail-rewrite and truncation (someone silently dropping or
replacing the most recent receipts). This is exactly a WARD tip
(``ward-sdk`` ``computeTip`` / ``signTipHash``): the signature is Ed25519 over
the hex ``tip_chain_hash``, so a QuoxProof tip and a WARD tip are the same
object by another name.

Honesty: a self-signed checkpoint is an anti-rewrite ANCHOR, not third-party
witnessing. It proves "this chain head is the one I checkpointed", which is
weaker than "an independent witness saw this chain" (the QuoxCORE/WARD witness
tier). The verifier reports it as its own rung and does not inflate it into
external witnessing.
"""

from __future__ import annotations

import uuid
from typing import Sequence

from .crypto import (
    Keypair,
    public_key_from_raw_b64,
    raw_public_key_b64,
    sign_hash,
    verify_hash_signature,
)
from .receipt import now_iso

TIP_VERSION = "0.1"


def build_tip(keypair: Keypair, session_id: str, receipts: Sequence[dict]) -> dict:
    """Build and sign a checkpoint over the head of ``receipts``."""
    if not receipts:
        raise ValueError("cannot checkpoint an empty chain")
    head = receipts[-1]
    tip_chain_hash = head["receipt_hash"]
    tip: dict = {
        "quoxproof_tip_version": TIP_VERSION,
        "tip_id": str(uuid.uuid4()),
        "session_id": session_id,
        "tip_seq": head["seq"],
        "entry_count": len(receipts),
        "tip_chain_hash": tip_chain_hash,
        "created_at": now_iso(),
    }
    tip["sig"] = {
        "sig_type": "ed25519",
        "key_id": keypair.key_id,
        "public_key": raw_public_key_b64(keypair.public_key),
        "signature": sign_hash(tip_chain_hash, keypair.private_key),
    }
    return tip


def verify_tip(
    tip: dict,
    receipts: Sequence[dict],
    pinned_public_key_b64: str | None = None,
) -> dict:
    """Check a checkpoint against a receipt chain.

    Returns {available, matches, sig_valid, tip_seq, reason?}. ``matches`` is
    true only when the chain's head hash and entry count equal the tip's, i.e.
    the chain has not been truncated or rewritten since the checkpoint.
    """
    result: dict = {"available": True, "tip_seq": tip.get("tip_seq")}
    sig = tip.get("sig")
    if not isinstance(sig, dict) or sig.get("sig_type") != "ed25519":
        return {**result, "matches": False, "sig_valid": False, "reason": "unsupported_or_missing_sig"}

    pub_b64 = pinned_public_key_b64 or sig.get("public_key")
    pub = public_key_from_raw_b64(pub_b64) if pub_b64 else None
    sig_valid = bool(pub) and verify_hash_signature(
        tip.get("tip_chain_hash", ""), sig.get("signature", ""), pub
    )
    if not sig_valid:
        return {**result, "matches": False, "sig_valid": False, "reason": "signature_invalid"}

    if not receipts:
        return {**result, "matches": False, "sig_valid": True, "reason": "empty_chain"}
    head = receipts[-1]
    matches = (
        head.get("receipt_hash") == tip.get("tip_chain_hash")
        and head.get("seq") == tip.get("tip_seq")
        and len(receipts) == tip.get("entry_count")
    )
    out = {**result, "matches": matches, "sig_valid": True}
    if not matches:
        out["reason"] = "chain_head_does_not_match_checkpoint"
    return out
