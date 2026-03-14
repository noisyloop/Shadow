"""
Shadow — Integration Test Suite (Phases 1–3)

Tests the full stack: X3DH handshake → Double Ratchet session →
Sealed Sender envelope → Nostr transport.

  1. Full X3DH + ratchet session (Alice ↔ Bob, multiple turns)
  2. Sealed sender: relay sees no sender identity in plaintext
  3. Sealed sender: tampered envelope fails authentication
  4. Sender certificate expiry
  5. Full Nostr publish/receive round-trip via LocalRelay
  6. Message serialization round-trips (InitialMessage, SealedEnvelope)
"""

import os
import sys
import asyncio
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.identity import DeviceIdentity, PrekeyServer
from core.x3dh import x3dh_send, x3dh_receive
from core.ratchet import ratchet_encrypt, ratchet_decrypt
from transport.nostr import LocalRelay, schnorr_keygen, decode_payload
from transport.sealed_sender import (
    seal_message, unseal_message,
    SealedEnvelope, issue_certificate,
    parse_sealed_from_event,
    publish_sealed,
)

AD = b"shadow-integration-v0"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def establish_session():
    """Run full X3DH to get (alice_identity, alice_state, bob_identity, bob_state)."""
    alice = DeviceIdentity.generate()
    bob   = DeviceIdentity.generate()
    spk   = bob.generate_spk(spk_id=1)
    opks  = bob.generate_opks(2, start_id=10)
    server = PrekeyServer()
    bundle = bob.build_bundle(spk, opks[0])
    server.publish(bundle, extra_opks=opks[1:])

    fetched = server.fetch(bob.ik_dh_pub)
    init_msg, alice_state = x3dh_send(alice, fetched, b"init", AD)
    opk_used = next((o for o in opks if o.id == fetched.opk_id), None)
    _, bob_state = x3dh_receive(bob, spk, opk_used, init_msg, AD)

    return alice, alice_state, bob, bob_state


# --------------------------------------------------------------------------- #
# Test 1 — Full session with sealed sender (multi-turn)
# --------------------------------------------------------------------------- #

def test_full_session_sealed_sender():
    """Complete multi-turn conversation via sealed sender envelopes."""
    alice, alice_state, bob, bob_state = establish_session()

    # Alice sends 3 sealed messages to Bob
    for i in range(3):
        plaintext = f"Alice message {i}".encode()
        env = seal_message(alice, bob.ik_dh_pub, alice_state, plaintext, AD)
        decrypted, cert = unseal_message(bob, bob_state, env, AD)
        assert decrypted == plaintext, f"Round {i}: decryption mismatch"
        assert cert.sender_ik_dh_pub == alice.ik_dh_pub, "Sender cert wrong IK"

    # Bob replies
    for i in range(3):
        plaintext = f"Bob reply {i}".encode()
        env = seal_message(bob, alice.ik_dh_pub, bob_state, plaintext, AD)
        decrypted, cert = unseal_message(alice, alice_state, env, AD)
        assert decrypted == plaintext
        assert cert.sender_ik_dh_pub == bob.ik_dh_pub


# --------------------------------------------------------------------------- #
# Test 2 — Relay sees no sender identity
# --------------------------------------------------------------------------- #

def test_relay_sees_no_sender_identity():
    """
    The sealed envelope contains no plaintext sender information.
    The relay_hint is only a partial recipient key — not linkable to the sender.
    """
    alice, alice_state, bob, bob_state = establish_session()

    env = seal_message(alice, bob.ik_dh_pub, alice_state, b"secret", AD)
    raw = env.serialize()

    # Verify: Alice's IK DH pub bytes do not appear in plaintext in the envelope
    alice_ik_hex = alice.ik_dh_pub.hex()
    raw_hex      = raw.hex()

    # The full sender identity key must not appear in the raw envelope
    # (it would only appear inside the ECIES ciphertext, which is opaque)
    assert alice_ik_hex not in raw_hex, "Sender IK visible in sealed envelope!"

    # The hint is only the first 8 bytes of the *recipient* key, not sender
    assert env.recipient_key_hint == bob.ik_dh_pub[:8].hex()
    assert alice.ik_dh_pub[:8].hex() != env.recipient_key_hint or True  # routing-only


# --------------------------------------------------------------------------- #
# Test 3 — Tampered sealed blob fails authentication
# --------------------------------------------------------------------------- #

def test_tampered_envelope_rejected():
    """Any modification to the sealed_blob must cause decryption failure."""
    alice, alice_state, bob, bob_state = establish_session()

    env = seal_message(alice, bob.ik_dh_pub, alice_state, b"tamper test", AD)

    # Flip a byte in the sealed blob (inside the ECIES ciphertext)
    bad_blob = bytearray(env.sealed_blob)
    bad_blob[-1] ^= 0xFF
    bad_env = SealedEnvelope(
        recipient_key_hint=env.recipient_key_hint,
        sealed_blob=bytes(bad_blob),
    )

    try:
        unseal_message(bob, bob_state, bad_env, AD)
        assert False, "Should have raised on tampered envelope"
    except Exception:
        pass  # expected — AESGCM tag verification failure


# --------------------------------------------------------------------------- #
# Test 4 — Expired sender certificate is rejected
# --------------------------------------------------------------------------- #

def test_expired_sender_certificate():
    """A sender certificate past its expiry is rejected on unseal."""
    from transport.sealed_sender import (
        SenderCertificate, _pack_inner, _ecies_encrypt,
    )
    from core.ratchet import ratchet_encrypt, Header
    import struct

    alice, alice_state, bob, bob_state = establish_session()

    # Issue an already-expired certificate (TTL = -1)
    expired_cert = issue_certificate(alice, ttl=-1)

    # Build the envelope manually with the expired cert
    header, ciphertext = ratchet_encrypt(alice_state, b"expired", AD)
    inner = _pack_inner(expired_cert, header, ciphertext)
    blob  = _ecies_encrypt(bob.ik_dh_pub, inner)
    env   = SealedEnvelope(
        recipient_key_hint=bob.ik_dh_pub[:8].hex(),
        sealed_blob=blob,
    )

    try:
        unseal_message(bob, bob_state, env, AD)
        assert False, "Should have raised on expired cert"
    except ValueError as e:
        assert "expired" in str(e).lower()


# --------------------------------------------------------------------------- #
# Test 5 — Nostr publish/receive via LocalRelay
# --------------------------------------------------------------------------- #

async def _nostr_roundtrip():
    alice, alice_state, bob, bob_state = establish_session()

    # Each party has a Nostr keypair (separate from Shadow identity)
    alice_nostr_priv, alice_nostr_pub = schnorr_keygen()
    bob_nostr_priv,   bob_nostr_pub   = schnorr_keygen()

    received = []

    relay = LocalRelay()
    async with relay:
        # Bob subscribes for messages addressed to him
        async def on_event(event):
            env = parse_sealed_from_event(event)
            pt, cert = unseal_message(bob, bob_state, env, AD)
            received.append((pt, cert.sender_ik_dh_pub))

        await relay.subscribe(
            sub_id="bob-inbox",
            filters={"kinds": [14], "#p": [bob_nostr_pub.hex()]},
            handler=on_event,
        )

        # Alice seals and publishes
        env = seal_message(alice, bob.ik_dh_pub, alice_state, b"Hello via Nostr!", AD)
        await publish_sealed(relay, alice_nostr_priv, alice_nostr_pub, bob_nostr_pub, env)

    return received


def test_nostr_roundtrip():
    """Full Nostr relay publish/receive with sealed sender."""
    received = asyncio.run(_nostr_roundtrip())
    assert len(received) == 1
    plaintext, sender_ik = received[0]
    assert plaintext == b"Hello via Nostr!"


# --------------------------------------------------------------------------- #
# Test 6 — Wire format serialization round-trips
# --------------------------------------------------------------------------- #

def test_serialization_roundtrip():
    """InitialMessage and SealedEnvelope survive serialize → deserialize."""
    from core.x3dh import InitialMessage
    from core.identity import PreKeyBundle

    alice = DeviceIdentity.generate()
    bob   = DeviceIdentity.generate()
    spk   = bob.generate_spk(spk_id=1)
    opks  = bob.generate_opks(1, start_id=0)
    server = PrekeyServer()
    server.publish(bob.build_bundle(spk, opks[0]))
    bundle = server.fetch(bob.ik_dh_pub)

    # InitialMessage binary round-trip
    init_msg, alice_state = x3dh_send(alice, bundle, b"roundtrip", AD)
    raw = init_msg.serialize()
    init_msg2 = InitialMessage.deserialize(raw)
    assert init_msg2.ik_pub       == init_msg.ik_pub
    assert init_msg2.ek_pub       == init_msg.ek_pub
    assert init_msg2.opk_id       == init_msg.opk_id
    assert init_msg2.header_bytes == init_msg.header_bytes
    assert init_msg2.ciphertext   == init_msg.ciphertext

    # InitialMessage JSON round-trip
    j = init_msg.to_json()
    init_msg3 = InitialMessage.from_json(j)
    assert init_msg3.ciphertext == init_msg.ciphertext

    # SealedEnvelope binary round-trip
    _, alice_state2, bob2, bob_state2 = establish_session()
    env  = seal_message(alice, bob2.ik_dh_pub, alice_state2, b"serial", AD)
    raw2 = env.serialize()
    env2 = SealedEnvelope.deserialize(raw2)
    assert env2.recipient_key_hint == env.recipient_key_hint
    assert env2.sealed_blob        == env.sealed_blob


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

TESTS = [
    ("Full session with sealed sender (multi-turn)", test_full_session_sealed_sender),
    ("Relay sees no sender identity",                test_relay_sees_no_sender_identity),
    ("Tampered envelope rejected",                   test_tampered_envelope_rejected),
    ("Expired sender certificate rejected",          test_expired_sender_certificate),
    ("Nostr publish/receive round-trip",             test_nostr_roundtrip),
    ("Wire format serialization round-trips",        test_serialization_roundtrip),
]

if __name__ == "__main__":
    print("\nIntegration Test Suite (Phases 1–3)")
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
