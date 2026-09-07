import math

import pytest

from quoxproof.canonical import canonicalize, is_well_formed_nfc, payload_hash, sha256_hex


def test_object_keys_sorted_at_every_level():
    assert canonicalize({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert canonicalize({"z": {"y": 1, "x": 2}}) == '{"z":{"x":2,"y":1}}'


def test_no_insignificant_whitespace():
    assert canonicalize({"a": [1, 2, 3]}) == '{"a":[1,2,3]}'


def test_primitives():
    assert canonicalize(None) == "null"
    assert canonicalize(True) == "true"
    assert canonicalize(False) == "false"
    assert canonicalize("hi") == '"hi"'


def test_integer_and_float_forms_match_js_string():
    assert canonicalize(2) == "2"
    assert canonicalize(-0) == "0"
    # a float that is integral drops the .0 (matches JS String(2.0) === "2")
    assert canonicalize(2.0) == "2"
    assert canonicalize(1.5) == "1.5"
    assert canonicalize(0.1) == "0.1"


def test_integer_bound_rejected():
    with pytest.raises(ValueError):
        canonicalize(2**53)  # outside +/-(2**53 - 1)
    assert canonicalize(2**53 - 1) == str(2**53 - 1)


def test_non_finite_rejected():
    for bad in (math.inf, -math.inf, math.nan):
        with pytest.raises(ValueError):
            canonicalize(bad)


def test_string_escaping_matches_js():
    # short escapes and \u00xx for other controls; non-ASCII and / stay raw
    assert canonicalize("a\nb\tc") == '"a\\nb\\tc"'
    assert canonicalize("\x01") == '"\\u0001"'
    assert canonicalize("a/b") == '"a/b"'
    assert canonicalize("héllo") == '"héllo"'


def test_nfc_rejected_not_repaired():
    # U+0065 U+0301 (e + combining acute) is NOT NFC; must be rejected
    decomposed = "é"
    assert not is_well_formed_nfc(decomposed)
    with pytest.raises(ValueError):
        canonicalize(decomposed)
    # its NFC form (é, U+00E9) is fine
    assert is_well_formed_nfc("é")
    assert canonicalize("é") == '"é"'


def test_payload_hash_is_stable_and_order_independent():
    a = payload_hash({"x": 1, "y": 2})
    b = payload_hash({"y": 2, "x": 1})
    assert a == b
    assert len(a) == 64
    assert a == sha256_hex('{"x":1,"y":2}')
