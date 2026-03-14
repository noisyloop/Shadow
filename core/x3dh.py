"""
Shadow — X3DH (Extended Triple Diffie-Hellman) Handshake
Reference: https://signal.org/docs/specifications/x3dh/

Alice (sender) and Bob (receiver) establish a shared secret asynchronously.
Bob does not need to be online when Alice initiates.

Flow:
  Alice fetches Bob's PreKeyBundle from the server.
  Alice verifies Bob's SPK signature.
  Alice computes 3–4 DH outputs and derives the shared secret SK.
  Alice initialises her Double Ratchet state and encrypts an initial message.
  Bob receives Alice's initial message, recomputes SK, initialises his ratchet,
  and decrypts.
"""

import os
import json
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .ratchet import (
    generate_dh, dh,
    ratchet_init_alice, ratchet_init_bob,
    ratchet_encrypt, ratchet_decrypt,
    Header, RatchetState,
)
from .identity import (
    DeviceIdentity, PreKeyBundle, SignedPreKey, OneTimePreKey, verify_bundle
)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Signal spec §2.2 — 32 0xFF bytes prepended to DH concatenation
_X3DH_F    = b"\xff" * 32
_X3DH_INFO = b"ShadowX3DH"
_X3DH_SALT = b"\x00" * 32


# --------------------------------------------------------------------------- #
# KDF
# --------------------------------------------------------------------------- #

def _kdf_x3dh(dh_outputs: list[bytes]) -> bytes:
    """
    KDF(F || DH1 || DH2 || DH3 [|| DH4]) → 32-byte SK
    HKDF-SHA256 with zero salt and domain-separation info.
    """
    ikm = _X3DH_F + b"".join(dh_outputs)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_X3DH_SALT,
        info=_X3DH_INFO,
    ).derive(ikm)


# --------------------------------------------------------------------------- #
# Wire format for Alice's initial message
# --------------------------------------------------------------------------- #

@dataclass
class InitialMessage:
    """
    Alice's initial message to Bob.
    Sent over the transport layer; Bob uses this to reconstruct SK.
    """
    ik_pub:       bytes          # Alice's IK DH public key (32 bytes)
    ek_pub:       bytes          # Alice's ephemeral key public (32 bytes)
    spk_id:       int            # which SPK Bob should use
    opk_id:       Optional[int]  # which OPK was used, or None
    header_bytes: bytes          # serialized Double Ratchet header (40 bytes)
    ciphertext:   bytes          # AES-GCM encrypted initial message

    def serialize(self) -> bytes:
        """Compact binary serialization for transport."""
        opk_id_bytes = struct.pack(">I", self.opk_id if self.opk_id is not None else 0xFFFFFFFF)
        has_opk = b"\x01" if self.opk_id is not None else b"\x00"
        hdr_len = struct.pack(">I", len(self.header_bytes))
        ct_len  = struct.pack(">I", len(self.ciphertext))
        return (
            self.ik_pub
            + self.ek_pub
            + struct.pack(">I", self.spk_id)
            + has_opk
            + opk_id_bytes
            + hdr_len
            + self.header_bytes
            + ct_len
            + self.ciphertext
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "InitialMessage":
        offset = 0
        ik_pub       = data[offset:offset+32];  offset += 32
        ek_pub       = data[offset:offset+32];  offset += 32
        spk_id       = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
        has_opk      = data[offset:offset+1] == b"\x01";              offset += 1
        opk_id_raw   = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
        opk_id       = opk_id_raw if has_opk else None
        hdr_len      = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
        header_bytes = data[offset:offset+hdr_len];                    offset += hdr_len
        ct_len       = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
        ciphertext   = data[offset:offset+ct_len]
        return cls(
            ik_pub=ik_pub,
            ek_pub=ek_pub,
            spk_id=spk_id,
            opk_id=opk_id,
            header_bytes=header_bytes,
            ciphertext=ciphertext,
        )

    def to_json(self) -> str:
        return json.dumps({
            "ik_pub":       self.ik_pub.hex(),
            "ek_pub":       self.ek_pub.hex(),
            "spk_id":       self.spk_id,
            "opk_id":       self.opk_id,
            "header_bytes": self.header_bytes.hex(),
            "ciphertext":   self.ciphertext.hex(),
        })

    @classmethod
    def from_json(cls, s: str) -> "InitialMessage":
        d = json.loads(s)
        return cls(
            ik_pub=bytes.fromhex(d["ik_pub"]),
            ek_pub=bytes.fromhex(d["ek_pub"]),
            spk_id=d["spk_id"],
            opk_id=d["opk_id"],
            header_bytes=bytes.fromhex(d["header_bytes"]),
            ciphertext=bytes.fromhex(d["ciphertext"]),
        )


# --------------------------------------------------------------------------- #
# X3DH sender (Alice)
# --------------------------------------------------------------------------- #

def x3dh_send(
    alice: DeviceIdentity,
    bob_bundle: PreKeyBundle,
    plaintext: bytes,
    AD: bytes,
) -> tuple[InitialMessage, RatchetState]:
    """
    Alice initiates X3DH with Bob.

    1. Verify Bob's SPK signature.
    2. Generate ephemeral key EK_A.
    3. Compute DH1..DH4 and derive SK.
    4. Initialise Double Ratchet and encrypt the initial plaintext.

    Returns (InitialMessage, alice_ratchet_state).
    The caller keeps alice_ratchet_state for all subsequent messages.
    """
    # Step 1 — verify SPK signature (raises InvalidSignature on failure)
    verify_bundle(bob_bundle)

    # Step 2 — ephemeral key
    ek_priv, ek_pub = generate_dh()

    # Step 3 — DH outputs
    dh1 = dh(alice.ik_dh_priv, bob_bundle.spk_public)   # DH(IK_A, SPK_B)
    dh2 = dh(ek_priv, bob_bundle.identity_key)           # DH(EK_A, IK_B)
    dh3 = dh(ek_priv, bob_bundle.spk_public)             # DH(EK_A, SPK_B)
    dh_outputs = [dh1, dh2, dh3]

    if bob_bundle.opk_public is not None:
        dh4 = dh(ek_priv, bob_bundle.opk_public)         # DH(EK_A, OPK_B)
        dh_outputs.append(dh4)

    SK = _kdf_x3dh(dh_outputs)

    # Step 4 — initialise ratchet and encrypt
    alice_state = ratchet_init_alice(SK, bob_bundle.spk_public)
    header, ct  = ratchet_encrypt(alice_state, plaintext, AD)

    return InitialMessage(
        ik_pub=alice.ik_dh_pub,
        ek_pub=ek_pub,
        spk_id=bob_bundle.spk_id,
        opk_id=bob_bundle.opk_id,
        header_bytes=header.serialize(),
        ciphertext=ct,
    ), alice_state


# --------------------------------------------------------------------------- #
# X3DH receiver (Bob)
# --------------------------------------------------------------------------- #

def x3dh_receive(
    bob: DeviceIdentity,
    spk: SignedPreKey,
    opk: Optional[OneTimePreKey],
    msg: InitialMessage,
    AD: bytes,
) -> tuple[bytes, RatchetState]:
    """
    Bob receives Alice's initial message and decrypts it.

    Bob looks up the SPK and OPK (if any) by ID from his own key store,
    recomputes the same DH outputs as Alice, derives SK, initialises his
    Double Ratchet, and decrypts.

    Returns (plaintext, bob_ratchet_state).
    The OPK should be deleted from Bob's store after this call.
    """
    # DH outputs — same combination, reversed roles
    dh1 = dh(spk.priv, msg.ik_pub)         # DH(SPK_B, IK_A)
    dh2 = dh(bob.ik_dh_priv, msg.ek_pub)   # DH(IK_B, EK_A)
    dh3 = dh(spk.priv, msg.ek_pub)         # DH(SPK_B, EK_A)
    dh_outputs = [dh1, dh2, dh3]

    if opk is not None:
        dh4 = dh(opk.priv, msg.ek_pub)     # DH(OPK_B, EK_A)
        dh_outputs.append(dh4)

    SK = _kdf_x3dh(dh_outputs)

    # Bob initialises with SPK as his current ratchet DH pair
    bob_state = ratchet_init_bob(SK, (spk.priv, spk.pub))
    header     = Header.deserialize(msg.header_bytes)
    plaintext  = ratchet_decrypt(bob_state, header, msg.ciphertext, AD)

    return plaintext, bob_state
