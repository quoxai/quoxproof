"""The unified QuoxProof receipt: one signed record per tool call.

A single receipt binds the three Quox evidence strands that, until now, only
existed separately (and only server-side):
  - AEE: the receipt is an evidence envelope with intent ``quox.tool.call.executed``.
  - VOLT: ``prev_hash`` + ``receipt_hash`` form a VOLT-style event chain.
  - WARD: ``receipt_hash`` is signed with the same Ed25519 scheme WARD tips use,
    so a run's head can be checkpointed as a WARD tip and witnessed.

Everything here is local-first: no server, no API key, no network. The receipt
carries its own public key, so it verifies offline.
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from typing import Any

from .canonical import canonicalize, sha256_hex
from .chain import GENESIS_PREV_HASH, compute_receipt_hash
from .crypto import Keypair, raw_public_key_b64, sign_hash

QUOXPROOF_VERSION = "0.1"
SDK_VERSION = "0.1.0"
TOOL_CALL_INTENT = "quox.tool.call.executed"

# Visibility modes mirror AEVS (public / private / proof_only) so the migration
# story is one-to-one, then go further with offline-verifiable hashes in every mode.
VISIBILITY_PUBLIC = "public"
VISIBILITY_PRIVATE = "private"
VISIBILITY_PROOF_ONLY = "proof_only"
_VISIBILITIES = {VISIBILITY_PUBLIC, VISIBILITY_PRIVATE, VISIBILITY_PROOF_ONLY}


def now_iso() -> str:
    """ISO 8601 UTC, second-or-finer, with a trailing Z."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_jsonable(value: Any) -> Any:
    """Coerce an arbitrary Python value into a JSON-canonicalisable projection.

    Names and structure are preserved where the value is already JSON-shaped;
    anything else (objects, callables) is reduced to its ``repr``. Non-finite
    floats become their repr so canonicalisation never chokes on them.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else repr(value)
    if isinstance(value, dict):
        return {str(k): safe_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe_jsonable(v) for v in value]
    return repr(value)


def hash_value(value: Any) -> str:
    """Privacy-preserving hash of a value via its canonical JSON projection."""
    return sha256_hex(canonicalize(safe_jsonable(value)))


def build_receipt(
    *,
    keypair: Keypair,
    seq: int,
    prev_hash: str,
    session_id: str,
    tool_name: str,
    inputs: Any,
    output: Any,
    status: str,
    error: dict | None,
    duration_ms: int,
    agent_id: str | None = None,
    tool_call_id: str | None = None,
    visibility: str = VISIBILITY_PRIVATE,
    captured_at: str | None = None,
    receipt_id: str | None = None,
    started_at: str | None = None,
    ended_at: str | None = None,
    framework: str = "direct",
    framework_version: str | None = None,
    run_id: str | None = None,
    parent_run_id: str | None = None,
    invocation_id: str | None = None,
) -> dict:
    """Build, hash, and sign one receipt. Pure: given the same inputs, same bytes.

    ``prev_hash`` for the first receipt in a chain is :data:`GENESIS_PREV_HASH`.
    Raw ``inputs``/``output`` are embedded only when ``visibility`` is
    ``public``; every mode always carries the hashes, so tamper-evidence and
    offline verification hold even in ``proof_only``.
    """
    if visibility not in _VISIBILITIES:
        raise ValueError(f"unknown visibility {visibility!r}; expected one of {_VISIBILITIES}")

    input_projection = safe_jsonable(inputs)
    output_projection = safe_jsonable(output)

    receipt: dict[str, Any] = {
        "quoxproof_version": QUOXPROOF_VERSION,
        "sdk_version": SDK_VERSION,
        "receipt_id": receipt_id or str(uuid.uuid4()),
        "session_id": session_id,
        "seq": seq,
        "intent": TOOL_CALL_INTENT,
        "tool_name": tool_name,
        "framework": framework,
        "captured_at": captured_at or now_iso(),
        "duration_ms": duration_ms,
        "status": status,
        "visibility": visibility,
        "input_hash": sha256_hex(canonicalize(input_projection)),
        "output_hash": sha256_hex(canonicalize(output_projection)),
        "prev_hash": prev_hash,
    }
    if agent_id is not None:
        receipt["agent_id"] = agent_id
    if tool_call_id is not None:
        receipt["tool_call_id"] = tool_call_id
    if framework_version is not None:
        receipt["framework_version"] = framework_version
    if started_at is not None:
        receipt["started_at"] = started_at
    if ended_at is not None:
        receipt["ended_at"] = ended_at
    if run_id is not None:
        receipt["run_id"] = run_id
    if parent_run_id is not None:
        receipt["parent_run_id"] = parent_run_id
    if invocation_id is not None:
        receipt["invocation_id"] = invocation_id
    receipt["error"] = error  # explicit null when status == "ok"
    if visibility == VISIBILITY_PUBLIC:
        receipt["input"] = input_projection
        receipt["output"] = output_projection

    receipt_hash = compute_receipt_hash(receipt)
    receipt["receipt_hash"] = receipt_hash
    receipt["sig"] = {
        "sig_type": "ed25519",
        "key_id": keypair.key_id,
        "public_key": raw_public_key_b64(keypair.public_key),
        "signature": sign_hash(receipt_hash, keypair.private_key),
    }
    return receipt


def reference_id_of(receipt: dict) -> str:
    """The opaque reference id a caller holds and hands to an auditor (AEVS parity)."""
    return receipt["receipt_id"]
