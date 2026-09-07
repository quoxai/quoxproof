"""QuoxProof CLI: verify, show, keygen. Offline, no network.

    quoxproof verify <path.ndjson> [--pubkey <b64>]
    quoxproof show <path.ndjson>
    quoxproof keygen [--out-dir DIR]

Also exposed as ``quox proof ...`` when wired into the quox CLI.
"""

from __future__ import annotations

import argparse
import json
import sys

from .store import ProofStore
from .verify import verify_chain

ICON = "\U0001f9fe"  # receipt glyph for QuoxProof


def _say(verb: str, result: str, ok: bool = True) -> None:
    glyph = "✔" if ok else "✖"
    sys.stderr.write(f"{ICON} QUOXPROOF │ {verb} │ {result} {glyph}\n")


def _cmd_verify(args: argparse.Namespace) -> int:
    store = ProofStore()
    receipts = store.load_path(args.path)
    result = verify_chain(receipts, pinned_public_key_b64=args.pubkey)
    intact = result["status"] == "INTACT"
    tl = result.get("trust_ladder", {})
    ks = tl.get("key_source")
    _say(
        f"verify {args.path}",
        f"{result['status']} · {result.get('receipt_count', 0)} receipts · "
        f"{result.get('signatures_verified', 0)} sigs · key:{ks}",
        ok=intact,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"status: {result['status']}")
        print(f"receipts: {result.get('receipt_count', 0)}")
        print(f"signatures_verified: {result.get('signatures_verified', 0)}")
        if intact:
            print("trust ladder:")
            print(f"  observe:            yes")
            print(f"  signature valid:    yes ({tl['sig']['verified']} receipts)")
            print(f"  chain intact:       yes")
            print(f"  key source:         {ks}"
                  f"{'  (self-consistent only, identity not verified)' if ks == 'embedded' else ''}")
            for rung in ("witnessed", "governed_execution", "external_attested"):
                info = tl.get(rung, {})
                print(f"  {rung}: not available  ({info.get('reason', '')})")
        else:
            print(f"reason: {result.get('reason')}")
            print(f"details: {json.dumps(result.get('details', {}))}")
    return 0 if intact else 1


def _cmd_show(args: argparse.Namespace) -> int:
    store = ProofStore()
    receipts = store.load_path(args.path)
    for r in receipts:
        line = (
            f"#{r.get('seq'):>3} {r.get('tool_name'):<20} "
            f"{r.get('status'):<5} {r.get('duration_ms')}ms "
            f"{r.get('receipt_hash', '')[:12]}… vis={r.get('visibility')}"
        )
        print(line)
    _say(f"show {args.path}", f"{len(receipts)} receipts")
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    store = ProofStore(args.out_dir)
    kp = store.keypair  # generates on first access
    _say("keygen", f"key_id {kp.key_id} · {store.public_key_pem_path()}")
    print(f"key_id: {kp.key_id}")
    print(f"public key: {store.public_key_pem_path()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="quoxproof", description="Offline-verifiable agent tool-call receipts")
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify", help="verify a receipt chain offline")
    v.add_argument("path", help="path to a session NDJSON file")
    v.add_argument("--pubkey", help="pin a raw base64 Ed25519 public key (identity-verify)")
    v.add_argument("--json", action="store_true", help="emit the full result as JSON")
    v.set_defaults(func=_cmd_verify)

    s = sub.add_parser("show", help="list receipts in a chain")
    s.add_argument("path", help="path to a session NDJSON file")
    s.set_defaults(func=_cmd_show)

    k = sub.add_parser("keygen", help="generate (or show) the local signing key")
    k.add_argument("--out-dir", help="store root (default ~/.quox/proofs)")
    k.set_defaults(func=_cmd_keygen)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
