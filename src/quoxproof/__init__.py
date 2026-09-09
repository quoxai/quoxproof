"""QuoxProof: offline-verifiable, Ed25519-signed receipts for every agent tool call.

The developer evidence SDK. Two lines to start:

    import quoxproof
    quoxproof.enable()

    @quoxproof.tool
    def search(query: str) -> str:
        ...

Every call to ``search`` writes a signed, hash-chained receipt to ``~/.quox/proofs/``.
Verify it later with no server, no account, no shared secret:

    quoxproof verify ~/.quox/proofs/<session>.ndjson

The difference from a backend audit service: the signature is Ed25519 (asymmetric)
and the public key travels in the receipt, so anyone can verify it offline. The
verifier reports the trust ladder honestly and never collapses it to one tick.
"""

from __future__ import annotations

from .canonical import canonicalize, payload_hash, sha256_hex
from .capture import (
    Recorder,
    checkpoint,
    clear_reference_ids,
    configure,
    disable,
    enable,
    flush,
    get_reference_id,
    get_reference_ids,
    get_session_id,
    is_healthy,
    reset_config,
    tool,
)
from .tip import build_tip, verify_tip
from .chain import GENESIS_PREV_HASH, compute_receipt_hash
from .crypto import (
    Keypair,
    ensure_keypair,
    generate_keypair,
    sign_hash,
    verify_hash_signature,
)
from .receipt import build_receipt, reference_id_of
from .store import ProofStore
from .verify import verify_chain

__version__ = "0.2.0"

__all__ = [
    "__version__",
    # capture / module API
    "configure",
    "enable",
    "disable",
    "tool",
    "flush",
    "is_healthy",
    "get_session_id",
    "get_reference_ids",
    "get_reference_id",
    "clear_reference_ids",
    "reset_config",
    "checkpoint",
    "build_tip",
    "verify_tip",
    "Recorder",
    # building blocks
    "build_receipt",
    "reference_id_of",
    "verify_chain",
    "ProofStore",
    "compute_receipt_hash",
    "GENESIS_PREV_HASH",
    # crypto / canonical
    "canonicalize",
    "payload_hash",
    "sha256_hex",
    "Keypair",
    "generate_keypair",
    "ensure_keypair",
    "sign_hash",
    "verify_hash_signature",
]
