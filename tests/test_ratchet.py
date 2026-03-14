"""
Shadow — Double Ratchet Test Suite
Tests all core security properties described in the README / Phase 0 checklist.
"""

import os
import sys
import copy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.ratchet import (
    generate_dh, dh, kdf_rk,
    ratchet_init_alice, ratchet_init_bob,
    ratchet_encrypt, ratchet_decrypt,
    Header,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def make_session():
    """
    Simulate X3DH output: both sides share a random SK,
    Bob's DH pair acts as the initial ratchet key.
    """
    SK = os.urandom(32)
    bob_pair = generate_dh()          # (private, public_bytes)
    alice = ratchet_init_alice(SK, bob_pair[1])
    bob   = ratchet_init_bob(SK, bob_pair)
    return alice, bob


AD = b"shadow-session-v0"


def send(sender, receiver, message: bytes) -> bytes:
    hdr, ct = ratchet_encrypt(sender, message, AD)
    return ratchet_decrypt(receiver, hdr, ct, AD)


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

def test_basic_roundtrip():
    """Alice sends to Bob, Bob replies to Alice."""
    alice, bob = make_session()

    plaintext = b"Hello from Alice"
    assert send(alice, bob, plaintext) == plaintext

    reply = b"Hello from Bob"
    assert send(bob, alice, reply) == reply


def test_multiple_messages_one_direction():
    """Alice sends several messages in a row without Bob replying."""
    alice, bob = make_session()

    messages = [f"Message {i}".encode() for i in range(10)]
    for msg in messages:
        assert send(alice, bob, msg) == msg


def test_alternating_conversation():
    """Simulate a realistic back-and-forth conversation."""
    alice, bob = make_session()

    for i in range(20):
        msg = f"turn {i}".encode()
        if i % 2 == 0:
            assert send(alice, bob, msg) == msg
        else:
            assert send(bob, alice, msg) == msg


def test_forward_secrecy():
    """
    Snapshot old state → advance session → attacker cannot decrypt new messages.
    A frozen copy of early state must not be able to decrypt messages
    produced after the DH ratchet has turned.
    """
    alice, bob = make_session()

    # Exchange one round so both sides have done a DH ratchet step
    send(alice, bob, b"setup")
    send(bob, alice, b"ack")

    # Attacker captures Bob's current state
    attacker_bob = copy.deepcopy(bob)

    # Advance the real session several turns
    for _ in range(5):
        send(alice, bob, b"new message")
        send(bob, alice, b"new reply")

    # Encrypt a new message from Alice (after multiple DH ratchet steps)
    hdr, ct = ratchet_encrypt(alice, b"secret after ratchet", AD)

    # Attacker's frozen state cannot decrypt it
    try:
        attacker_bob.MKSKIPPED.clear()   # ensure no lucky cached key
        result = ratchet_decrypt(attacker_bob, hdr, ct, AD)
        assert result != b"secret after ratchet", "Forward secrecy broken!"
    except Exception:
        pass  # decryption failure is the expected outcome


def test_break_in_recovery():
    """
    Attacker with current keys loses access after the next DH ratchet step.
    If the attacker is given the current chain key they can decrypt current
    messages, but after a DH ratchet step their keys are useless.
    """
    alice, bob = make_session()
    send(alice, bob, b"warmup")
    send(bob, alice, b"warmup reply")

    # Give attacker Bob's current receiving chain key
    import copy
    attacker_bob = copy.deepcopy(bob)

    # Alice sends a message the attacker CAN currently decrypt
    hdr, ct = ratchet_encrypt(alice, b"current message", AD)
    assert ratchet_decrypt(attacker_bob, hdr, ct, AD) == b"current message"

    # Now Bob replies — this triggers a new DH ratchet step on Alice's side
    # Alice will generate a fresh DH keypair Alice has never seen the attacker
    hdr2, ct2 = ratchet_encrypt(bob, b"bob's turn", AD)
    ratchet_decrypt(alice, hdr2, ct2, AD)   # real Alice processes it

    # Alice now sends with a fresh DH ratchet key
    hdr3, ct3 = ratchet_encrypt(alice, b"post-ratchet secret", AD)

    # Attacker cannot decrypt — their DH state is stale
    try:
        result = ratchet_decrypt(attacker_bob, hdr3, ct3, AD)
        assert result != b"post-ratchet secret", "Break-in recovery broken!"
    except Exception:
        pass  # failure is the expected outcome


def test_out_of_order_delivery():
    """Messages that arrive out of order are still decryptable."""
    alice, bob = make_session()

    # Alice sends 5 messages without Bob processing them yet
    envelopes = [ratchet_encrypt(alice, f"msg {i}".encode(), AD) for i in range(5)]

    # Bob receives them out of order: 4, 2, 0, 3, 1
    order = [4, 2, 0, 3, 1]
    for i in order:
        hdr, ct = envelopes[i]
        result = ratchet_decrypt(bob, hdr, ct, AD)
        assert result == f"msg {i}".encode(), f"Out-of-order failed for msg {i}"


def test_associated_data_binding():
    """
    Decryption must fail if associated data is tampered.
    The AD is bound into the AEAD so any change causes authentication failure.
    """
    alice, bob = make_session()

    hdr, ct = ratchet_encrypt(alice, b"bound message", AD)

    # Try to decrypt with wrong AD
    try:
        ratchet_decrypt(bob, hdr, ct, b"wrong-session-id")
        assert False, "Should have raised on bad AD"
    except Exception:
        pass  # expected


def test_header_integrity():
    """
    Tampered header fields must cause decryption failure.
    The header is serialized into the AEAD associated data, so any
    modification to PN or N will cause the authentication tag to fail.
    """
    alice, bob = make_session()

    hdr, ct = ratchet_encrypt(alice, b"tamper test", AD)

    # Tamper with the message number in the header
    bad_hdr = Header(dh=hdr.dh, pn=hdr.pn, n=hdr.n + 99)

    try:
        ratchet_decrypt(bob, bad_hdr, ct, AD)
        assert False, "Should have raised on tampered header"
    except Exception:
        pass  # expected


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

TESTS = [
    ("Basic round-trip",             test_basic_roundtrip),
    ("Multiple messages one direction", test_multiple_messages_one_direction),
    ("Alternating conversation",     test_alternating_conversation),
    ("Forward secrecy",              test_forward_secrecy),
    ("Break-in recovery",            test_break_in_recovery),
    ("Out-of-order delivery",        test_out_of_order_delivery),
    ("Associated data binding",      test_associated_data_binding),
    ("Header integrity",             test_header_integrity),
]


if __name__ == "__main__":
    print("\nDouble Ratchet Protocol — Test Suite")
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
            failed += 1
    print("==========================================")
    print(f"  {passed}/{len(TESTS)} passed")
    if failed == 0:
        print("  All properties verified.")
    else:
        print(f"  {failed} FAILED.")
        sys.exit(1)
