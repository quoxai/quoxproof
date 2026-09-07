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

Status: MVP. Local signing, chaining, and offline verification are driven end to
end. LangChain and MCP auto-hooks are wired; QuoxCORE witnessing and governed
execution are the upgrade tiers.
