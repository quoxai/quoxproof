"""QUOXTRUST F9 (engagement c4, FND_01M3R1V6A3DDJDP3YE3VDDJDP3) —
the offline verifier binds sig.key_id to the verifying key.

A receipt's ``sig.key_id`` is an IDENTITY claim: which key signed. The verifier
checked the Ed25519 signature against the embedded (or pinned) ``public_key`` but
never checked that ``key_id`` actually corresponds to that key. So an attacker
could present a TRUSTED signer's ``key_id`` alongside their own ``public_key`` and
a valid signature, and any consumer trusting ``sig.key_id`` as "who signed" is
deceived — the SkillRights RFC 6962 unbound-attacker-writable-field class.

``derive_key_id(public_key)`` already exists (crypto.py); the fix enforces it.

Agreement (accept AND reject), per the deliberate-duplication rule: the verifier
must ACCEPT a receipt whose key_id matches its verifying key and REJECT one whose
key_id was swapped, for both the embedded-key and pinned-key paths.
"""
import copy

from quoxproof.chain import GENESIS_PREV_HASH
from quoxproof.crypto import generate_keypair, derive_key_id, raw_public_key_b64
from quoxproof.receipt import build_receipt
from quoxproof.verify import verify_chain


def _one(keypair, visibility="private"):
    return build_receipt(
        keypair=keypair,
        seq=1,
        prev_hash=GENESIS_PREV_HASH,
        session_id="sess-1",
        tool_name="tool_1",
        inputs={"args": [1], "kwargs": {}},
        output="out1",
        status="ok",
        error=None,
        duration_ms=10,
        visibility=visibility,
    )


def test_honest_receipt_key_id_matches_its_public_key():
    kp = generate_keypair()
    r = _one(kp)
    # The receipt's claimed key_id is the derivation of its own public key.
    assert r["sig"]["key_id"] == derive_key_id(kp.public_key)
    assert verify_chain([r])["status"] == "INTACT"


def test_swapped_key_id_is_rejected_embedded_key():
    # Attacker claims a trusted signer's key_id but embeds their OWN public key
    # and a genuine signature over the receipt_hash. The signature verifies, but
    # the identity claim is a lie: must be rejected.
    attacker = generate_keypair()
    victim = generate_keypair()
    r = _one(attacker)
    r["sig"]["key_id"] = derive_key_id(victim.public_key)  # borrowed identity

    result = verify_chain([r])
    assert result["status"] == "BROKEN", "a receipt whose key_id does not match its verifying key must not verify green"
    assert result["reason"] == "SIGNATURE_INVALID"
    assert result["details"]["reason"] == "key_id_mismatch"


def test_swapped_key_id_is_rejected_pinned_key():
    kp = generate_keypair()
    r = _one(kp)
    r["sig"]["key_id"] = "deadbeefdeadbeef"  # a claim inconsistent with the pinned/verifying key

    result = verify_chain([r], pinned_public_key_b64=raw_public_key_b64(kp.public_key))
    assert result["status"] == "BROKEN"
    assert result["details"]["reason"] == "key_id_mismatch"


def test_absent_key_id_does_not_crash():
    # A sig with no key_id carries no identity claim to bind — still verifies on
    # signature validity alone (unchanged behaviour, no false rejection).
    kp = generate_keypair()
    r = _one(kp)
    del r["sig"]["key_id"]
    assert verify_chain([r])["status"] == "INTACT"
