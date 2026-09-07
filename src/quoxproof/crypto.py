"""Ed25519 signing for QuoxProof receipts.

Deliberately Ed25519 (asymmetric), never HMAC. This is the core difference from
AEVS: an AEVS local receipt is HMAC-signed with a secret shared with Fetch.ai's
backend, so it cannot be verified without their server and your API key. A
QuoxProof receipt is Ed25519-signed and carries the raw public key, so anyone
can verify it offline with no account, no backend, no shared secret.

Conventions are byte-compatible with ward-sdk (``sign.ts``) and volt-sdk
(``sign.ts``):
  - ``key_id`` = last 32 bytes of the SPKI DER (the raw public key), hex, first
    16 chars.
  - A signature is Ed25519 over the raw UTF-8 bytes of the hash hex string
    (ward-sdk ``signTipHash`` convention), base64-encoded. So a QuoxProof
    receipt's signature verifies with the same primitive as a WARD tip.
  - The embedded public key is the raw 32 bytes, base64 (volt-sdk
    ``rawPublicKeyBase64`` convention), reconstructible via the fixed SPKI
    prefix ``302a300506032b6570032100``.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# SPKI wrapper for a raw 32-byte Ed25519 public key:
# 30 2a 30 05 06 03 2b 65 70 03 21 00 <32-byte key>
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _spki_der(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def derive_key_id(public_key: Ed25519PublicKey) -> str:
    """Stable 16-hex-char fingerprint: last 32 bytes of SPKI DER, hex, first 16."""
    der = _spki_der(public_key)
    return der[-32:].hex()[:16]


def raw_public_key_b64(public_key: Ed25519PublicKey) -> str:
    """The raw 32-byte public key, base64 (volt-sdk convention)."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def public_key_from_raw_b64(public_key_b64: str) -> Ed25519PublicKey | None:
    """Reconstruct an Ed25519 public key from a raw 32-byte base64 string."""
    try:
        raw = base64.b64decode(public_key_b64)
        if len(raw) != 32:
            return None
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None


@dataclass
class Keypair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    key_id: str


def generate_keypair() -> Keypair:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return Keypair(private_key=priv, public_key=pub, key_id=derive_key_id(pub))


def sign_hash(hash_hex: str, private_key: Ed25519PrivateKey) -> str:
    """Ed25519 over the raw UTF-8 bytes of ``hash_hex``; returns base64.

    Matches ward-sdk ``signTipHash``: sign the hex string's bytes, not the
    32 raw digest bytes, so signatures are interchangeable across the SDKs.
    """
    sig = private_key.sign(hash_hex.encode("utf-8"))
    return base64.b64encode(sig).decode("ascii")


def verify_hash_signature(
    hash_hex: str, signature_b64: str, public_key: Ed25519PublicKey
) -> bool:
    """Verify an Ed25519 signature over a hash hex string. Never raises."""
    try:
        public_key.verify(base64.b64decode(signature_b64), hash_hex.encode("utf-8"))
        return True
    except (InvalidSignature, Exception):
        return False


def export_keypair(keypair: Keypair, pub_path: str, priv_path: str) -> None:
    """Export a keypair to PEM files (private key mode 0600)."""
    pub_pem = keypair.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_pem = keypair.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    # Create the private key file with 0600 from the outset (no world-readable window).
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, priv_pem)
    finally:
        os.close(fd)
    os.chmod(priv_path, 0o600)


def load_keypair(pub_path: str, priv_path: str) -> Keypair:
    with open(priv_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("load_keypair: private key is not Ed25519")
    pub = priv.public_key()
    return Keypair(private_key=priv, public_key=pub, key_id=derive_key_id(pub))


def ensure_keypair(pub_path: str, priv_path: str) -> Keypair:
    """Load a keypair if both PEM files exist, else generate and persist one."""
    if os.path.exists(pub_path) and os.path.exists(priv_path):
        return load_keypair(pub_path, priv_path)
    kp = generate_keypair()
    export_keypair(kp, pub_path, priv_path)
    return kp
