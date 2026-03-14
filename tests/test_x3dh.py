"""
Shadow — X3DH Test Suite

Tests all Phase 1 properties:
  1. Full handshake: Alice initiates with Bob offline, Bob receives and decrypts
  2. OPK is consumed and not reused
  3. Session works when no OPK is available (graceful degradation)
  4. Bad SPK signature is rejected
"""

import os
import sys
import copy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.identity import DeviceIdentity, PrekeyServer, generate_opk_batch
from core.x3dh import x3dh_send, x3dh_receive
from core.ratchet import ratchet_encrypt, ratchet_decrypt


AD = b"shadow-x3dh-test-v0"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def setup_bob(opk_count: int = 3):
    """Create Bob's device identity, register on prekey server, return state."""
    bob      = DeviceIdentity.generate()
    spk      = bob.generate_spk(spk_id=1)
    opks     = bob.generate_opks(opk_count, start_id=100)
    server   = PrekeyServer()
    # First OPK is included directly in the initial bundle; rest go in the pool
    bundle   = bob.build_bundle(spk, opks[0] if opks else None)
    server.publish(bundle, extra_opks=opks[1:] if len(opks) > 1 else [])
    return bob, spk, opks, server


# --------------------------------------------------------------------------- #
# Test 1 — Full handshake
# --------------------------------------------------------------------------- #

def test_full_handshake():
    """Alice initiates with Bob offline; Bob receives and decrypts correctly."""
    bob, spk, opks, server = setup_bob(opk_count=3)
    alice = DeviceIdentity.generate()

    # Alice fetches Bob's bundle (Bob is offline)
    bundle = server.fetch(bob.ik_dh_pub)
    assert bundle is not None

    initial_plaintext = b"Hello Bob, this is Alice!"
    init_msg, alice_state = x3dh_send(alice, bundle, initial_plaintext, AD)

    # Alice sends more messages using the ratchet before Bob comes online
    h1, ct1 = ratchet_encrypt(alice_state, b"Second message", AD)
    h2, ct2 = ratchet_encrypt(alice_state, b"Third message",  AD)

    # Bob comes online and processes Alice's initial message
    opk_used = next((o for o in opks if o.id == bundle.opk_id), None)
    decrypted, bob_state = x3dh_receive(bob, spk, opk_used, init_msg, AD)
    assert decrypted == initial_plaintext

    # Bob decrypts subsequent messages
    assert ratchet_decrypt(bob_state, h1, ct1, AD) == b"Second message"
    assert ratchet_decrypt(bob_state, h2, ct2, AD) == b"Third message"

    # Bob replies
    hb, ctb = ratchet_encrypt(bob_state, b"Hi Alice!", AD)
    assert ratchet_decrypt(alice_state, hb, ctb, AD) == b"Hi Alice!"


# --------------------------------------------------------------------------- #
# Test 2 — OPK consumed and not reused
# --------------------------------------------------------------------------- #

def test_opk_consumed():
    """
    Each X3DH session should consume a distinct OPK.
    After all OPKs are exhausted the server returns None for opk_public.
    """
    bob, spk, opks, server = setup_bob(opk_count=3)
    alice = DeviceIdentity.generate()

    used_opk_ids = set()

    # Exhaust all 3 OPKs across 3 sessions (4th will have no OPK)
    for i in range(3):
        bundle = server.fetch(bob.ik_dh_pub)
        assert bundle is not None
        if bundle.opk_id is not None:
            assert bundle.opk_id not in used_opk_ids, "OPK reused!"
            used_opk_ids.add(bundle.opk_id)

    # Fourth fetch — no OPK should be returned (pool exhausted)
    bundle_no_opk = server.fetch(bob.ik_dh_pub)
    assert bundle_no_opk is not None
    assert bundle_no_opk.opk_public is None
    assert bundle_no_opk.opk_id is None

    assert len(used_opk_ids) == 3, "Expected exactly 3 unique OPKs"


# --------------------------------------------------------------------------- #
# Test 3 — Graceful degradation without OPK
# --------------------------------------------------------------------------- #

def test_no_opk_graceful_degradation():
    """Session still works when no OPK is available."""
    bob, spk, opks, server = setup_bob(opk_count=0)
    alice = DeviceIdentity.generate()

    bundle = server.fetch(bob.ik_dh_pub)
    assert bundle is not None
    assert bundle.opk_public is None  # no OPKs published

    plaintext = b"No OPK, still works"
    init_msg, alice_state = x3dh_send(alice, bundle, plaintext, AD)

    # opk=None signals no OPK was used
    decrypted, bob_state = x3dh_receive(bob, spk, None, init_msg, AD)
    assert decrypted == plaintext

    # Full duplex works
    h, ct = ratchet_encrypt(bob_state, b"Bob reply", AD)
    assert ratchet_decrypt(alice_state, h, ct, AD) == b"Bob reply"


# --------------------------------------------------------------------------- #
# Test 4 — Bad SPK signature is rejected
# --------------------------------------------------------------------------- #

def test_bad_spk_signature_rejected():
    """Alice must reject a bundle whose SPK signature does not verify."""
    from cryptography.exceptions import InvalidSignature

    bob, spk, opks, server = setup_bob(opk_count=1)
    alice = DeviceIdentity.generate()

    bundle = server.fetch(bob.ik_dh_pub)

    # Tamper: replace SPK public key but keep original signature
    from core.identity import PreKeyBundle
    from core.ratchet import generate_dh
    _, fake_spk_pub = generate_dh()
    tampered = PreKeyBundle(
        identity_key=bundle.identity_key,
        identity_sign_key=bundle.identity_sign_key,
        spk_id=bundle.spk_id,
        spk_public=fake_spk_pub,          # <-- tampered
        spk_signature=bundle.spk_signature,  # original sig (now invalid)
        opk_id=bundle.opk_id,
        opk_public=bundle.opk_public,
    )

    try:
        x3dh_send(alice, tampered, b"should fail", AD)
        assert False, "Should have raised InvalidSignature"
    except InvalidSignature:
        pass  # expected


# --------------------------------------------------------------------------- #
# Test 5 — OPK replenishment
# --------------------------------------------------------------------------- #

def test_opk_replenishment():
    """
    Server signals needs_replenishment when pool drops below the low-water mark.
    replenish_opks() refills the pool and subsequent fetches succeed with an OPK.
    """
    bob, spk, opks, server = setup_bob(opk_count=3)
    ik_hex = bob.ik_dh_pub.hex()

    # Fetch 1 — 2 OPKs remain after pop; 2 < OPK_LOW_WATER_MARK(5) → True
    b1 = server.fetch(bob.ik_dh_pub)
    assert b1 is not None and b1.opk_id is not None
    assert b1.needs_replenishment is True  # 2 remaining < 5

    # Fetch 2 — 1 OPK remains
    b2 = server.fetch(bob.ik_dh_pub)
    assert b2 is not None and b2.opk_id is not None
    assert b2.needs_replenishment is True  # 1 remaining < 5

    # Fetch 3 — pool is now empty → needs_replenishment must be True
    b3 = server.fetch(bob.ik_dh_pub)
    assert b3 is not None and b3.opk_id is not None
    assert b3.needs_replenishment is True  # 0 remaining < 5

    # Replenish with 5 new OPKs
    new_opks = generate_opk_batch(bob, count=5, existing_opks=opks)
    server.replenish_opks(ik_hex, [(o.id, o.pub) for o in new_opks])

    # Pool should now contain 5 OPKs
    assert server.opk_count(ik_hex) == 5

    # Fetch again — should succeed and return an OPK
    b4 = server.fetch(bob.ik_dh_pub)
    assert b4 is not None
    assert b4.opk_id is not None
    assert b4.opk_public is not None


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

TESTS = [
    ("Full handshake (Alice offline initiation)",  test_full_handshake),
    ("OPK consumed and not reused",                test_opk_consumed),
    ("Graceful degradation without OPK",           test_no_opk_graceful_degradation),
    ("Bad SPK signature rejected",                 test_bad_spk_signature_rejected),
    ("OPK replenishment",                          test_opk_replenishment),
]

if __name__ == "__main__":
    print("\nX3DH Handshake — Test Suite")
    print("==========================================")
    passed = 0
    failed = 0
    for name, fn in TESTS:
        try:
            fn()
            print(f"  \u2713  {name}")
            passed += 1
        except Exception as e:
            print(f"  \u2717  {name}: {e}")
            import traceback; traceback.print_exc()
            failed += 1
    print("==========================================")
    print(f"  {passed}/{len(TESTS)} passed")
    if failed == 0:
        print("  All properties verified.")
    else:
        print(f"  {failed} FAILED.")
        sys.exit(1)
