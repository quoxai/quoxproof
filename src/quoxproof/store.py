"""Local-first receipt store: append-only NDJSON under ~/.quox/proofs/.

No server required. Each session is one NDJSON file, one receipt per line, in
seq order. Writes are flushed and fsync'd so a crash mid-run cannot leave a
torn line. The signing keypair lives under ``keys/`` (private key 0600) and is
generated on first use. This is the whole persistence tier for the MVP: a
QuoxCORE collector is an optional upgrade, not a dependency.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .chain import GENESIS_PREV_HASH
from .crypto import Keypair, ensure_keypair

DEFAULT_ROOT = Path(os.path.expanduser("~/.quox/proofs"))


class ProofStore:
    """Filesystem-backed, append-only store of signed receipts."""

    def __init__(self, root: str | os.PathLike | None = None) -> None:
        self.root = Path(root) if root is not None else DEFAULT_ROOT
        self._keys_dir = self.root / "keys"
        self._lock = threading.Lock()
        self.root.mkdir(parents=True, exist_ok=True)
        self._keys_dir.mkdir(parents=True, exist_ok=True)
        self._keypair: Keypair | None = None

    @property
    def keypair(self) -> Keypair:
        if self._keypair is None:
            pub = str(self._keys_dir / "quoxproof_ed25519.pub")
            priv = str(self._keys_dir / "quoxproof_ed25519.pem")
            self._keypair = ensure_keypair(pub, priv)
        return self._keypair

    def public_key_pem_path(self) -> Path:
        return self._keys_dir / "quoxproof_ed25519.pub"

    def session_path(self, session_id: str) -> Path:
        # Session ids are uuids/opaque; guard against path traversal regardless.
        safe = session_id.replace("/", "_").replace("..", "_")
        return self.root / f"{safe}.ndjson"

    def head(self, session_id: str) -> tuple[int, str]:
        """Return (last_seq, last_receipt_hash) for a session, or (0, genesis)."""
        path = self.session_path(session_id)
        if not path.exists():
            return 0, GENESIS_PREV_HASH
        last_line = ""
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if not last_line:
            return 0, GENESIS_PREV_HASH
        rec = json.loads(last_line)
        return int(rec["seq"]), str(rec["receipt_hash"])

    def append(self, session_id: str, receipt: dict) -> None:
        """Append one receipt as an NDJSON line, flushed and fsync'd."""
        path = self.session_path(session_id)
        line = json.dumps(receipt, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            with path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())

    def load_session(self, session_id: str) -> list[dict]:
        """Load all receipts for a session in file order."""
        path = self.session_path(session_id)
        if not path.exists():
            return []
        receipts: list[dict] = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    receipts.append(json.loads(line))
        return receipts

    def load_path(self, path: str | os.PathLike) -> list[dict]:
        """Load receipts from an explicit NDJSON path (for the verify CLI)."""
        p = Path(path)
        receipts: list[dict] = []
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    receipts.append(json.loads(line))
        return receipts
