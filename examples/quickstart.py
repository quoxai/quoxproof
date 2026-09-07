"""QuoxProof in ten lines: decorate, run, verify offline.

    python examples/quickstart.py
    quoxproof verify ~/.quox/proofs/quickstart.ndjson
"""

import quoxproof

quoxproof.configure(agent_id="quickstart", session_id="quickstart", visibility="public")


@quoxproof.tool
def search(query: str) -> str:
    return f"top result for {query}"


if __name__ == "__main__":
    search("verifiable agents")
    search("offline receipts")
    print("session:", quoxproof.get_session_id())
    for ref in quoxproof.get_reference_ids():
        print(f"  #{ref['seq']} {ref['tool_name']} -> {ref['reference_id']}")
    path = quoxproof.capture._active().store.session_path("quickstart")
    print(f"\nreceipts written to: {path}")
    print(f"verify offline with: quoxproof verify {path}")
