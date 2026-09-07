"""Side by side: the same two-line opt-in, then the difference that matters.

AEVS and QuoxProof feel identical to adopt. The difference shows up the moment
someone other than you, without your account, tries to verify a receipt.

    # AEVS (needs an account + backend)
    import aevs
    aevs.configure(api_key="aevs_sk_...", agent_id="...")
    aevs.enable()
    # ... use your tools ...
    refs = aevs.get_reference_ids()      # opaque ids; verify == ask the backend

    # QuoxProof (local-first, offline-verifiable)
    import quoxproof
    quoxproof.configure(agent_id="...")  # no api key
    quoxproof.enable()
    # ... use your tools ...
    # verify with: quoxproof verify ~/.quox/proofs/<session>.ndjson   (no backend)

This script runs the QuoxProof half for real and then verifies a receipt with a
from-scratch check that does NOT import quoxproof.verify, to show the receipt is
genuinely self-contained: public key in the receipt, no shared secret, no server.
"""

import base64
import hashlib
import json

import quoxproof
from quoxproof.canonical import canonicalize
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

quoxproof.configure(agent_id="demo", session_id="aevs-vs-quoxproof", visibility="public")


@quoxproof.tool
def transfer(amount: float, to: str) -> str:
    return f"queued transfer of {amount} to {to}"


if __name__ == "__main__":
    transfer(100.0, "acct-42")
    path = quoxproof.capture._active().store.session_path("aevs-vs-quoxproof")
    receipt = [json.loads(line) for line in open(path) if line.strip()][0]

    # A third party, holding ONLY the receipt bytes, verifies it:
    body = {k: v for k, v in receipt.items() if k not in ("receipt_hash", "sig")}
    hash_ok = hashlib.sha256(canonicalize(body).encode()).hexdigest() == receipt["receipt_hash"]
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(receipt["sig"]["public_key"]))
    try:
        pub.verify(base64.b64decode(receipt["sig"]["signature"]), receipt["receipt_hash"].encode())
        sig_ok = True
    except Exception:
        sig_ok = False

    print(f"tool: {receipt['tool_name']}  status: {receipt['status']}")
    print(f"offline hash check:      {hash_ok}")
    print(f"offline signature check: {sig_ok}")
    print(f"key source:              embedded in receipt (no backend, no shared secret)")
    print("\nAn AEVS receipt's payload_hmac is HMAC-SHA256 with an HKDF-derived")
    print("secret (default keys), so this same offline check is impossible without")
    print("Fetch.ai's backend and your API secret. That is the whole difference.")
