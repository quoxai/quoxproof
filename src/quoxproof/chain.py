"""Local hash-chain math for QuoxProof receipts (VOLT section 7 conventions).

Each receipt carries a ``prev_hash`` (the previous receipt's ``receipt_hash``,
or the genesis all-zeros hash for the first) and a ``receipt_hash`` computed as
SHA-256 over the canonical JSON of the receipt with its ``receipt_hash`` and
``sig`` fields removed. This is the same construction as volt-sdk ``eventHash`` /
``chainEvents``, so a QuoxProof chain is a VOLT event chain by another name.
"""

from __future__ import annotations

from typing import Any, Mapping

from .canonical import canonicalize, sha256_hex

# VOLT SPEC section 7.2: the genesis (seq=1) receipt's prev_hash is 64 hex zeros.
GENESIS_PREV_HASH = "0" * 64

# Fields excluded from the hash body: the hash itself, and the signature over it.
_NON_BODY_FIELDS = ("receipt_hash", "sig")


def receipt_hash_body(receipt: Mapping[str, Any]) -> dict:
    """The receipt with ``receipt_hash`` and ``sig`` removed (the hash preimage)."""
    return {k: v for k, v in receipt.items() if k not in _NON_BODY_FIELDS}


def compute_receipt_hash(receipt: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical JSON of the receipt's hash body."""
    return sha256_hex(canonicalize(receipt_hash_body(receipt)))
