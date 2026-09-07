# QuoxProof vs AEVS: a source-verified parity matrix

This is the factual basis for any public comparison. Every AEVS claim below was
verified by reading the installed `aevs` 0.2.2 package source (in an isolated
venv), not from marketing copy. File references are to the installed package.

## How AEVS actually works (verified from source)

- **Adoption:** `aevs.configure(api_key="aevs_sk_...", agent_id=...)` then
  `aevs.enable()`. Two lines. Auto-hooks LangChain/LangGraph and MCP. There is
  no per-function decorator in the public API (`dir(aevs)` 0.2.2).
- **Receipt schema** (`aevs/core/types.py`, `ReceiptPayload`): reference_id,
  session_id, agent_id, seq, prev_hash, tool_name, inputs, output, status,
  error, started_at, ended_at, duration_ms, run_id, parent_run_id,
  invocation_id, sdk_version, framework, framework_version, receipt_visibility,
  **payload_hmac**. In `proof_only` mode inputs/output are dropped and
  input_hash/output_hash added.
- **Tamper field** (`aevs/core/receipt.py`): the receipt's integrity lives in
  `payload_hmac`.
  - Default keys (`aevs_sk_`, auth v1): `payload_hmac` is **HMAC-SHA256** over
    the canonical receipt bytes, keyed by `derive_key(key_secret,
    salt="aevs-payload-v1")` (HKDF, `aevs/crypto/hkdf.py`). Symmetric: only a
    holder of that secret (the backend, or anyone with your API secret) can
    verify it.
  - v2 keys (`aevs_sk2_`): `payload_hmac` holds an **ECDSA P-256** signature
    (`ecdsa_sign_payload_v2`). Asymmetric, but the receipt carries **no public
    key field**, so offline verification still needs the key out of band.
- **Chain** (`aevs/crypto/chain.py`): `prev_hash` = SHA-256 of the full prior
  receipt; the genesis anchor (`compute_chain_anchor`) is **derived from the
  secret key** and the session id. Recomputing the chain from scratch needs the
  secret.
- **Delivery + verification:** a background drainer POSTs receipts to
  `POST /v1/receipts`; verification is a **backend lookup by reference_id**. The
  public explorer showed 0 receipts at launch.
- **Blockchain:** none in the SDK. (Stork's write-up called it "on-chain"; the
  source has no chain/smart-contract component. The owner's read was correct.)

## The matrix

| Dimension | AEVS 0.2.2 | QuoxProof 0.1 |
|---|---|---|
| Two-line opt-in | yes | yes |
| LangChain / MCP auto-hooks | yes | yes (driven against langchain-core 1.6.2 + mcp 2.x) |
| Per-function decorator | no | **yes** (`@quoxproof.tool`, transparent) |
| Module API | configure/enable/disable/flush/get_reference_id(s)/get_session_id/is_healthy/clear_reference_ids/reset_config | same set, one-to-one |
| Visibility modes | public / private / proof_only | same three; hashes present in **every** mode |
| Receipt signing | payload_hmac: HMAC-SHA256 (default) or ECDSA P-256 (v2) | **Ed25519** signature over the receipt hash |
| Public key in receipt | no | **yes** (raw 32-byte, embedded) |
| Offline third-party verify | **no** (backend lookup; HKDF secret / KMS key) | **yes** (proven: independent re-impl + cross-language WARD verify) |
| Local-first / no account | no (api_key required, POSTs to backend) | **yes** (`~/.quox/proofs/`, no key, no network) |
| Chain genesis | secret-derived anchor | public constant (64 zeros) |
| Verifier honesty | receipt == "recorded" | **trust ladder**: sig / chain / key-source / witnessed / governed-execution / external-attested, never collapsed |
| Prove the action ran (not just recorded) | out of scope | QuoxCORE governed-execution tier (L3+) |
| Blockchain | none | none (by design) |

## Where AEVS is ahead today (honest)

- **Hosted explorer + shareable links.** AEVS ships a backend and a public
  receipt explorer URL. QuoxProof's explorer is the QuoxCORE tier / roadmap; the
  local MVP verifies from the CLI.
- **CrewAI adapter** is on their near-term list. QuoxProof ships LangChain + MCP;
  CrewAI is a straightforward next adapter.

## The one-line honest pitch

Same two lines to adopt. The difference is the trust boundary: an AEVS receipt is
verified by asking Fetch.ai's backend; a QuoxProof receipt is verified by anyone,
offline, with the public key it carries, and the verifier tells you exactly what
it can and cannot prove.
