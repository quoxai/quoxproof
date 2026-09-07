"""Canonical JSON for hashing, profile WARD-CANON-1 (a faithful Python port).

This is a byte-for-byte port of the ``canonicalize()`` in ward-sdk
(``ward-sdk/src/crypto.ts``, profile WARD-CANON-1) and compatible with the
VOLT canonical form for the ASCII-keyed objects QuoxProof receipts carry. The
whole point is determinism: the same receipt hashes to the same value here, in
the TypeScript ward-sdk, and in the VOLT recorder, so a QuoxProof receipt can
be verified by any of them. The cross-language parity is asserted by
``tests/test_cross_language.py`` (Python vs the real ward-sdk in node).

Rules (WARD-CANON-1, SPEC section 3.2):
  1. UTF-8, no insignificant whitespace.
  2. Object keys sorted by UTF-8 byte order at every nesting level.
  3. Strings MUST be well-formed Unicode and already in NFC; a string that is
     not is REJECTED (raised), never silently repaired.
  4. Integers are bounded to +/-(2**53 - 1) and serialised in exact decimal
     form (no leading zeros, no plus sign). Non-finite numbers are rejected.
     A finite non-integer whose shortest form needs exponent notation is
     rejected (not canonical-safe).
  5. Duplicate member names must be rejected by the parser feeding this
     function; already-parsed Python dicts cannot represent a duplicate key,
     so that rule is enforced at the byte-parsing boundary, not here.
"""

from __future__ import annotations

import hashlib
import math
import unicodedata
from typing import Any

# 2**53 - 1, the WARD-CANON-1 integer magnitude bound (SPEC section 3.2 rule 4).
MAX_SAFE_MAGNITUDE = 9007199254740991

# Short escapes matching JavaScript JSON.stringify exactly. Every other control
# character below 0x20 becomes \u00xx (lowercase); non-ASCII stays raw UTF-8
# (JSON.stringify does not escape it, and neither does this), and "/" is not
# escaped. This keeps byte-parity with the TS canonical form.
_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def is_well_formed_nfc(s: str) -> bool:
    """True if ``s`` is well-formed Unicode (no surrogate code points) and NFC."""
    for ch in s:
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF:
            return False
    return unicodedata.normalize("NFC", s) == s


def _json_string(s: str) -> str:
    """Serialise a string exactly as JavaScript JSON.stringify would."""
    out = ['"']
    for ch in s:
        esc = _SHORT_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(value: float) -> str:
    if isinstance(value, bool):  # bool is a subclass of int; handle upstream
        raise TypeError("bool is not a number here")
    if isinstance(value, int):
        if value > MAX_SAFE_MAGNITUDE or value < -MAX_SAFE_MAGNITUDE:
            raise ValueError(
                f"canonicalize: integer {value} is outside the WARD-CANON-1 "
                "range +/-(2**53 - 1)"
            )
        return str(value)
    # float
    if not math.isfinite(value):
        raise ValueError(f"canonicalize: non-finite number is not serialisable: {value}")
    if value.is_integer():
        iv = int(value)
        if iv > MAX_SAFE_MAGNITUDE or iv < -MAX_SAFE_MAGNITUDE:
            raise ValueError(
                f"canonicalize: integer {iv} is outside the WARD-CANON-1 range"
            )
        return str(iv)
    s = repr(value)  # shortest round-trip decimal, matches JS String(number)
    if "e" in s or "E" in s:
        raise ValueError(
            f"canonicalize: number {s} requires exponent notation, not canonical-safe"
        )
    return s


def canonicalize(value: Any) -> str:
    """Return the WARD-CANON-1 canonical JSON string for ``value``."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        if not is_well_formed_nfc(value):
            raise ValueError(
                "canonicalize: string is not well-formed Unicode in NFC "
                "(WARD-CANON-1 rule 3 rejects, never repairs): "
                f"{value!r}"
            )
        return _json_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = list(value.keys())
        for k in keys:
            if not isinstance(k, str):
                raise TypeError(f"canonicalize: object key must be a string, got {type(k)}")
            if not is_well_formed_nfc(k):
                raise ValueError(
                    "canonicalize: object key is not well-formed Unicode in NFC "
                    f"(WARD-CANON-1 rule 3): {k!r}"
                )
        keys.sort(key=lambda k: k.encode("utf-8"))
        pairs = [_json_string(k) + ":" + canonicalize(value[k]) for k in keys]
        return "{" + ",".join(pairs) + "}"
    raise TypeError(f"canonicalize: unsupported type {type(value)}")


def sha256_hex(text: str) -> str:
    """SHA-256 of a UTF-8 string, lowercase hex (64 chars)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def payload_hash(obj: Any) -> str:
    """SHA-256 of an object via its canonical JSON."""
    return sha256_hex(canonicalize(obj))
