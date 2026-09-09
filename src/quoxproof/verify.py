"""Offline verifier for a QuoxProof receipt chain.

No server, no account, no shared secret: given a list of receipts and (optionally)
a pinned public key, this recomputes every hash and checks every signature
locally. The result deliberately does NOT collapse to one green tick. It reports
each rung of the trust ladder separately, because a receipt proving "the SDK
recorded this call" is a weaker claim than "this action ran through a governed
plane", and conflating them is the dishonesty this whole product exists to avoid.

Trust ladder (each reported on its own):
  L0 observe            - the receipt exists and is well-formed
  L1 sig                - the Ed25519 signature over receipt_hash is valid
  L1 chain              - prev_hash linkage + recomputed receipt_hash all match
  key_source            - 'pinned' (identity-verified out of band) vs
                          'embedded' (self-consistent only: proves the record is
                          internally intact, NOT who signed it)
  L2 witnessed          - a WARD tip countersigns the head (server/witness tier)
  L3 governed_execution - the action ran through the Quox governed plane
  L4 external_attested  - an external result was independently attested
The rungs above L1 are not decidable from a local receipt alone; they are
reported as ``available: false`` with an honest reason rather than false/true.
"""

from __future__ import annotations

from typing import Any, Sequence

from .chain import GENESIS_PREV_HASH, compute_receipt_hash
from .crypto import public_key_from_raw_b64, verify_hash_signature

_HEX64 = set("0123456789abcdef")
_REQUIRED_FIELDS = (
    "quoxproof_version",
    "receipt_id",
    "session_id",
    "seq",
    "tool_name",
    "captured_at",
    "duration_ms",
    "status",
    "visibility",
    "input_hash",
    "output_hash",
    "prev_hash",
    "receipt_hash",
    "sig",
)


def _is_hex64(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in _HEX64 for c in v)


def _higher_rungs() -> dict:
    """The rungs a local receipt cannot decide on its own, reported honestly."""
    return {
        "witnessed": {
            "available": False,
            "reason": "no WARD tip supplied; witnessing is the QuoxCORE/server tier",
        },
        "governed_execution": {
            "available": False,
            "reason": "not decidable from a local receipt; requires the Quox governed plane",
        },
        "external_attested": {
            "available": False,
            "reason": "external result attestation is a separate, higher rung",
        },
    }


def _checkpoint_rung(tip: dict | None, receipts: Sequence[dict], pinned: str | None) -> dict:
    """The checkpoint rung: honest about anchor-vs-witness (see tip.py)."""
    if tip is None:
        return {
            "available": False,
            "reason": "no checkpoint supplied; run `quoxproof checkpoint` to pin the chain head",
        }
    from .tip import verify_tip

    return verify_tip(tip, receipts, pinned_public_key_b64=pinned)


def verify_chain(
    receipts: Sequence[dict],
    pinned_public_key_b64: str | None = None,
    tip: dict | None = None,
) -> dict:
    """Verify an ordered receipt chain. ``receipts`` MUST be seq-ascending.

    Returns a result dict with an overall ``status`` in {INTACT, BROKEN},
    per-receipt findings, and the trust ladder. An empty chain is INTACT.
    An optional ``tip`` (a signed checkpoint) adds the anti-rewrite rung.
    """
    per_receipt: list[dict] = []
    signatures_verified = 0
    key_sources: set[str] = set()

    if not receipts:
        return {
            "status": "INTACT",
            "receipt_count": 0,
            "signatures_verified": 0,
            "chain_intact": True,
            "trust_ladder": {
                "observe": True,
                "sig": {"all_valid": True, "verified": 0},
                "chain": True,
                "key_source": None,
                "checkpoint": _checkpoint_rung(tip, receipts, pinned_public_key_b64),
                **_higher_rungs(),
            },
            "receipts": [],
        }

    prev = GENESIS_PREV_HASH
    for index, receipt in enumerate(receipts):
        expected_seq = index + 1
        finding: dict[str, Any] = {"seq": receipt.get("seq"), "receipt_id": receipt.get("receipt_id")}

        # L0 - well-formedness.
        missing = [f for f in _REQUIRED_FIELDS if f not in receipt]
        if missing:
            return _broken(per_receipt, finding, "SCHEMA_INVALID", {"missing": missing})
        for f in ("input_hash", "output_hash", "prev_hash", "receipt_hash"):
            if not _is_hex64(receipt[f]):
                return _broken(per_receipt, finding, "SCHEMA_INVALID", {"field": f, "rule": "hex64"})

        # Contiguous seq from 1.
        if receipt["seq"] != expected_seq:
            return _broken(
                per_receipt, finding, "SEQ_INVALID",
                {"expected_seq": expected_seq, "found_seq": receipt["seq"]},
            )

        # Linkage.
        if receipt["prev_hash"] != prev:
            return _broken(
                per_receipt, finding, "CHAIN_LINK_BROKEN",
                {"expected_prev": prev, "found_prev": receipt["prev_hash"]},
            )

        # L1 chain - recompute receipt_hash.
        computed = compute_receipt_hash(receipt)
        if computed != receipt["receipt_hash"]:
            return _broken(
                per_receipt, finding, "RECEIPT_HASH_MISMATCH",
                {"expected": computed, "found": receipt["receipt_hash"]},
            )

        # L1 sig - verify the Ed25519 signature over receipt_hash.
        sig = receipt["sig"]
        sig_valid = False
        key_source = None
        reason = None
        if not isinstance(sig, dict) or sig.get("sig_type") != "ed25519":
            reason = "unsupported_or_missing_sig"
        else:
            pub_b64 = None
            if pinned_public_key_b64 is not None:
                pub_b64 = pinned_public_key_b64
                key_source = "pinned"
            elif sig.get("public_key"):
                pub_b64 = sig["public_key"]
                key_source = "embedded"
            else:
                reason = "no_key_available"
            if pub_b64 is not None:
                pub = public_key_from_raw_b64(pub_b64)
                if pub is None:
                    reason = "bad_public_key"
                    key_source = None
                else:
                    sig_valid = verify_hash_signature(
                        receipt["receipt_hash"], sig.get("signature", ""), pub
                    )
                    if not sig_valid:
                        reason = "signature_mismatch"

        if not sig_valid:
            return _broken(
                per_receipt, finding, "SIGNATURE_INVALID",
                {"key_source": key_source, "reason": reason},
            )
        signatures_verified += 1
        if key_source:
            key_sources.add(key_source)

        finding.update({"chain_ok": True, "sig_valid": True, "key_source": key_source})
        per_receipt.append(finding)
        prev = receipt["receipt_hash"]

    overall_key_source = (
        "pinned" if key_sources == {"pinned"}
        else "embedded" if key_sources == {"embedded"}
        else "mixed"
    )
    return {
        "status": "INTACT",
        "receipt_count": len(receipts),
        "signatures_verified": signatures_verified,
        "chain_intact": True,
        "trust_ladder": {
            "observe": True,
            "sig": {"all_valid": True, "verified": signatures_verified},
            "chain": True,
            "key_source": overall_key_source,
            "checkpoint": _checkpoint_rung(tip, receipts, pinned_public_key_b64),
            **_higher_rungs(),
        },
        "receipts": per_receipt,
    }


def _broken(per_receipt: list, finding: dict, reason: str, details: dict) -> dict:
    finding.update({"chain_ok": False, "sig_valid": False, "failure": reason, "details": details})
    per_receipt.append(finding)
    return {
        "status": "BROKEN",
        "reason": reason,
        "details": {**details, "seq": finding.get("seq"), "receipt_id": finding.get("receipt_id")},
        "chain_intact": False,
        "receipts": per_receipt,
    }
