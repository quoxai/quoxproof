# QuoxProof

Offline-verifiable, Ed25519-signed receipts for every AI agent tool call.

```python
import quoxproof
quoxproof.enable()

@quoxproof.tool
def search(query: str) -> str:
    return f"results for {query}"

search("agentic AI")
```

Every call writes a signed, hash-chained receipt to `~/.quox/proofs/`. Verify it
later with no server, no account, no shared secret:

```
quoxproof verify ~/.quox/proofs/<session>.ndjson
```

## Why it is different

A backend audit service signs receipts with a secret shared with its own server,
so a receipt cannot be checked without that server and your API key. QuoxProof
signs with Ed25519 (asymmetric) and carries the public key in the receipt, so
anyone can verify it offline. The verifier reports the trust ladder honestly and
never collapses it to a single green tick: a receipt that proves "the SDK
recorded this call" is a weaker claim than "this action ran through a governed
plane", and QuoxProof says which one it can back.

## Checkpoints (anti-rewrite anchor)

Pin the head of a chain with a signed checkpoint, then detect any later
truncation or tail-rewrite:

```
quoxproof checkpoint ~/.quox/proofs/<session>.ndjson     # writes <session>.tip.json
quoxproof verify ~/.quox/proofs/<session>.ndjson --tip ~/.quox/proofs/<session>.tip.json
```

A checkpoint is a WARD tip by another name (Ed25519 over the head hash). It is an
anti-rewrite anchor, not third-party witnessing, and the verifier says so.

## In-browser viewer

`viewer/receipt-viewer.html` is a single self-contained page: drop a receipt file
(and optionally a checkpoint) and it verifies the signatures and hash chain in your
browser via WebCrypto. No install, no upload, no backend.

Status: local signing, chaining, checkpoints, and offline verification are driven
end to end (Python + an in-browser verifier). LangChain and MCP auto-hooks are
driven against the real frameworks. QuoxCORE witnessing and governed execution are
the upgrade tiers.
