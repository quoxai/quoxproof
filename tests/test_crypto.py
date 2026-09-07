from quoxproof.crypto import (
    derive_key_id,
    generate_keypair,
    public_key_from_raw_b64,
    raw_public_key_b64,
    sign_hash,
    verify_hash_signature,
)


def test_sign_verify_roundtrip():
    kp = generate_keypair()
    h = "a" * 64
    sig = sign_hash(h, kp.private_key)
    assert verify_hash_signature(h, sig, kp.public_key)


def test_wrong_hash_fails_verification():
    kp = generate_keypair()
    sig = sign_hash("a" * 64, kp.private_key)
    assert not verify_hash_signature("b" * 64, sig, kp.public_key)


def test_wrong_key_fails_verification():
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    sig = sign_hash("a" * 64, kp1.private_key)
    assert not verify_hash_signature("a" * 64, sig, kp2.public_key)


def test_raw_pubkey_reconstruct_roundtrip():
    kp = generate_keypair()
    b64 = raw_public_key_b64(kp.public_key)
    reconstructed = public_key_from_raw_b64(b64)
    assert reconstructed is not None
    # a signature verifies against the reconstructed key
    sig = sign_hash("c" * 64, kp.private_key)
    assert verify_hash_signature("c" * 64, sig, reconstructed)


def test_key_id_is_stable_and_16_hex():
    kp = generate_keypair()
    kid = derive_key_id(kp.public_key)
    assert kid == kp.key_id
    assert len(kid) == 16
    assert all(c in "0123456789abcdef" for c in kid)


def test_bad_pubkey_returns_none():
    assert public_key_from_raw_b64("not-base64!!") is None
    assert public_key_from_raw_b64("YWJj") is None  # 3 bytes, not 32
