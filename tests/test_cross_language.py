"""Cross-language parity: the Python WARD-CANON-1 port must produce byte-identical
canonical JSON and identical SHA-256 hashes to the real ward-sdk (TypeScript).

This is what backs the claim that a QuoxProof receipt is verifiable by the
existing offline WARD tooling, not just by QuoxProof's own verifier. It shells
out to node against ward-sdk/dist; if node or the compiled dist is missing, it
skips (the claim is then simply unproven in this environment, not silently
assumed).
"""

import json
import os
import shutil
import subprocess

import pytest

from quoxproof.canonical import canonicalize, payload_hash

_HELPER = os.path.join(os.path.dirname(__file__), "ward_canonical_parity.mjs")
_WARD_DIST = "/home/control/ward-sdk/dist/src/crypto.js"

# ASCII-keyed values in the shape receipts actually take. (WARD-CANON-1 and the
# VOLT canonical form only diverge on non-ASCII KEYS, which receipts never have.)
CASES = [
    {"b": 1, "a": 2},
    {"z": {"y": 1, "x": 2}, "arr": [3, 2, 1]},
    {"quoxproof_version": "0.1", "seq": 1, "duration_ms": 123, "status": "ok", "error": None},
    {"tool_name": "search", "input_hash": "a" * 64, "nested": {"k": [True, False, None]}},
    {"unicode": "héllo wörld", "slash": "a/b", "newline": "x\ny"},
    {"int_max_safe": 9007199254740991, "float": 1.5, "zero": 0},
    [1, 2, {"deep": [{"deeper": "value"}]}],
    "a plain string",
    42,
    True,
]


@pytest.mark.skipif(
    shutil.which("node") is None or not os.path.exists(_WARD_DIST),
    reason="node or ward-sdk/dist not available; cross-language parity unproven here",
)
def test_python_canonical_matches_ward_sdk():
    proc = subprocess.run(
        ["node", _HELPER],
        input=json.dumps(CASES),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"node helper failed: {proc.stderr}"
    ward = json.loads(proc.stdout)
    assert len(ward) == len(CASES)

    mismatches = []
    for value, expected in zip(CASES, ward):
        py_canon = canonicalize(value)
        py_hash = payload_hash(value)
        if py_canon != expected["canonical"]:
            mismatches.append(("canonical", value, py_canon, expected["canonical"]))
        if py_hash != expected["hash"]:
            mismatches.append(("hash", value, py_hash, expected["hash"]))
    assert not mismatches, "\n".join(str(m) for m in mismatches)
