"""
Shadow — Sealed Sender (Phase 3)

Hides metadata — who is messaging whom — from the relay.
The relay sees only the destination key, not the sender.

Design:
  Outer envelope (visible to relay):
    - recipient_key_hint: first 8 bytes of recipient IK DH pub, hex-encoded
      (enough for routing; not a full identifier)
    - sealed_blob: opaque bytes, ECIES-encrypted for the recipient

  Inside sealed_blob (decrypted only by recipient):
    - sender_certificate: sender's IK pub + signing pub + expiry + self-signature
    - ratchet_header: serialized Double Ratchet message header
    - ciphertext: Double Ratchet encrypted message body

Sender certificate:
  Short-lived credential that proves identity to the recipient only.
  The relay never sees it.

ECIES construction for sealed_blob:
  1. Generate ephemeral X25519 key (eph_priv, eph_pub)
  2. shared = DH(eph_priv, recipient_IK_dh_pub)
  3. enc_key = HKDF(shared, salt=eph_pub, info=b"ShadowSealedSender")
  4. Encrypt with AES-256-GCM

Wire format (all big-endian lengths):
  sealed_blob = eph_pub (32) || nonce (12) || ciphertext+tag
  inner       = cert_len (4) || cert || hdr_len (4) || hdr || ct_len (4) || ct
"""

import os
import json
import time
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

from core.ratchet import (
    RatchetState, Header,
    ratchet_encrypt, ratchet_decrypt,
)
from core.identity import DeviceIdentity
from transport.nostr import (
    NostrEvent, build_event, decode_payload, LocalRelay,
    schnorr_keygen,
)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

CERT_TTL_SECONDS   = 24 * 3600   # sender certificates valid for 24 hours
SEALED_SENDER_INFO = b"ShadowSealedSender"


# --------------------------------------------------------------------------- #
# ECIES helpers
# --------------------------------------------------------------------------- #

def _ecies_encrypt(recipient_dh_pub: bytes, plaintext: bytes) -> bytes:
    """
    ECIES encrypt plaintext for recipient.
    Returns: eph_pub (32) || nonce (12) || ciphertext+tag

    AAD = eph_pub binds the ciphertext to the ephemeral key so that
    swapping eph_pub in the blob is detected by GCM authentication.
    """
    eph_priv_obj = X25519PrivateKey.generate()
    eph_priv     = eph_priv_obj.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    eph_pub      = eph_priv_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    shared  = eph_priv_obj.exchange(X25519PublicKey.from_public_bytes(recipient_dh_pub))
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_pub,
        info=SEALED_SENDER_INFO,
    ).derive(shared)

    nonce = os.urandom(12)
    ct    = AESGCM(enc_key).encrypt(nonce, plaintext, eph_pub)
    return eph_pub + nonce + ct


def _ecies_decrypt(recipient_dh_priv: bytes, blob: bytes) -> bytes:
    """
    ECIES decrypt. blob = eph_pub (32) || nonce (12) || ciphertext+tag
    """
    if len(blob) < 44 + 16:   # 32 eph_pub + 12 nonce + 16 GCM tag minimum
        raise ValueError("Sealed blob too short to be a valid ECIES envelope")

    eph_pub  = blob[:32]
    nonce    = blob[32:44]
    ct       = blob[44:]

    priv_obj = X25519PrivateKey.from_private_bytes(recipient_dh_priv)
    shared   = priv_obj.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    enc_key  = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_pub,
        info=SEALED_SENDER_INFO,
    ).derive(shared)

    return AESGCM(enc_key).decrypt(nonce, ct, eph_pub)


# --------------------------------------------------------------------------- #
# Sender certificate
# --------------------------------------------------------------------------- #

@dataclass
class SenderCertificate:
    """
    Short-lived credential that authenticates the sender to the recipient.
    Never visible to the relay.
    """
    sender_ik_dh_pub:   bytes   # sender's X25519 IK DH public key (32 bytes)
    sender_sign_pub:    bytes   # sender's ed25519 signing public key (32 bytes)
    expires_at:         int     # unix timestamp

    # signature = ed25519_sign(ik_dh_pub || sign_pub || expires_at_bytes)
    signature:          bytes   # 64 bytes

    def serialize(self) -> bytes:
        body = (
            self.sender_ik_dh_pub
            + self.sender_sign_pub
            + struct.pack(">Q", self.expires_at)
        )
        return body + struct.pack(">I", len(self.signature)) + self.signature

    @classmethod
    def deserialize(cls, data: bytes) -> "SenderCertificate":
        ik_dh_pub  = data[:32]
        sign_pub   = data[32:64]
        expires_at = struct.unpack(">Q", data[64:72])[0]
        sig_len    = struct.unpack(">I", data[72:76])[0]
        signature  = data[76:76+sig_len]
        return cls(
            sender_ik_dh_pub=ik_dh_pub,
            sender_sign_pub=sign_pub,
            expires_at=expires_at,
            signature=signature,
        )

    def verify(self) -> None:
        """
        Verify the certificate's self-signature.
        Raises InvalidSignature or ValueError on failure.
        """
        if int(time.time()) > self.expires_at:
            raise ValueError("Sender certificate has expired")
        body = (
            self.sender_ik_dh_pub
            + self.sender_sign_pub
            + struct.pack(">Q", self.expires_at)
        )
        pub = Ed25519PublicKey.from_public_bytes(self.sender_sign_pub)
        pub.verify(self.signature, body)   # raises InvalidSignature on bad sig


def issue_certificate(identity: DeviceIdentity, ttl: int = CERT_TTL_SECONDS) -> SenderCertificate:
    """Issue a fresh sender certificate signed by the device identity."""
    expires_at = int(time.time()) + ttl
    body = (
        identity.ik_dh_pub
        + identity.ik_sign_pub
        + struct.pack(">Q", expires_at)
    )
    signature = identity.sign(body)
    return SenderCertificate(
        sender_ik_dh_pub=identity.ik_dh_pub,
        sender_sign_pub=identity.ik_sign_pub,
        expires_at=expires_at,
        signature=signature,
    )


# --------------------------------------------------------------------------- #
# Inner payload (inside sealed_blob)
# --------------------------------------------------------------------------- #

def _pack_inner(cert: SenderCertificate, header: Header, ciphertext: bytes) -> bytes:
    cert_bytes = cert.serialize()
    hdr_bytes  = header.serialize()
    return (
        struct.pack(">I", len(cert_bytes)) + cert_bytes
        + struct.pack(">I", len(hdr_bytes)) + hdr_bytes
        + struct.pack(">I", len(ciphertext)) + ciphertext
    )


def _unpack_inner(data: bytes) -> tuple[SenderCertificate, Header, bytes]:
    _MIN_INNER = 4 + 76 + 4 + 40 + 4 + 0   # cert_len_field + min_cert + hdr_len_field + hdr + ct_len_field
    if len(data) < _MIN_INNER:
        raise ValueError(f"Inner payload too short: {len(data)} bytes")

    offset = 0

    # Sender certificate
    if offset + 4 > len(data):
        raise ValueError("Truncated inner payload: missing cert_len")
    cert_len = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
    if cert_len > len(data) - offset:
        raise ValueError(f"cert_len {cert_len} exceeds remaining buffer {len(data) - offset}")
    cert = SenderCertificate.deserialize(data[offset:offset+cert_len]); offset += cert_len

    # Ratchet header
    if offset + 4 > len(data):
        raise ValueError("Truncated inner payload: missing hdr_len")
    hdr_len = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
    if hdr_len > len(data) - offset:
        raise ValueError(f"hdr_len {hdr_len} exceeds remaining buffer {len(data) - offset}")
    hdr = Header.deserialize(data[offset:offset+hdr_len]); offset += hdr_len

    # Ciphertext
    if offset + 4 > len(data):
        raise ValueError("Truncated inner payload: missing ct_len")
    ct_len = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
    if ct_len > len(data) - offset:
        raise ValueError(f"ct_len {ct_len} exceeds remaining buffer {len(data) - offset}")
    ct = data[offset:offset+ct_len]

    return cert, hdr, ct


# --------------------------------------------------------------------------- #
# Outer envelope
# --------------------------------------------------------------------------- #

@dataclass
class SealedEnvelope:
    """
    The full sealed sender envelope.
    Only recipient_key_hint is visible to the relay.
    sealed_blob is opaque.
    """
    recipient_key_hint: str    # hex of first 8 bytes of recipient IK DH pub
    sealed_blob: bytes         # ECIES-encrypted inner payload

    def serialize(self) -> bytes:
        hint_bytes = bytes.fromhex(self.recipient_key_hint)
        return (
            struct.pack(">I", len(hint_bytes)) + hint_bytes
            + struct.pack(">I", len(self.sealed_blob)) + self.sealed_blob
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "SealedEnvelope":
        offset  = 0
        hint_len = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
        hint     = data[offset:offset+hint_len].hex();             offset += hint_len
        blob_len = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
        blob     = data[offset:offset+blob_len]
        return cls(recipient_key_hint=hint, sealed_blob=blob)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def seal_message(
    sender:          DeviceIdentity,
    recipient_ik_pub: bytes,
    ratchet_state:   RatchetState,
    plaintext:       bytes,
    AD:              bytes,
) -> SealedEnvelope:
    """
    Encrypt a message using the Double Ratchet, then wrap it in a sealed sender
    envelope so the transport layer (relay) cannot determine the sender.

    Returns a SealedEnvelope ready to be published over Nostr (or any transport).
    """
    cert   = issue_certificate(sender)
    header, ciphertext = ratchet_encrypt(ratchet_state, plaintext, AD)
    inner  = _pack_inner(cert, header, ciphertext)
    blob   = _ecies_encrypt(recipient_ik_pub, inner)
    hint   = recipient_ik_pub[:8].hex()
    return SealedEnvelope(recipient_key_hint=hint, sealed_blob=blob)


def unseal_message(
    recipient:       DeviceIdentity,
    ratchet_state:   RatchetState,
    envelope:        SealedEnvelope,
    AD:              bytes,
) -> tuple[bytes, SenderCertificate]:
    """
    Decrypt a sealed sender envelope.

    1. ECIES-decrypt the sealed_blob with the recipient's IK DH private key.
    2. Extract and verify the sender certificate.
    3. Double Ratchet decrypt the message body.

    Returns (plaintext, sender_certificate).
    Raises on any authentication failure.
    """
    inner  = _ecies_decrypt(recipient.ik_dh_priv, envelope.sealed_blob)
    cert, header, ciphertext = _unpack_inner(inner)
    cert.verify()    # raises if expired or signature invalid
    plaintext = ratchet_decrypt(ratchet_state, header, ciphertext, AD)
    return plaintext, cert


# --------------------------------------------------------------------------- #
# Nostr integration helpers
# --------------------------------------------------------------------------- #

async def publish_sealed(
    relay,
    sender_nostr_priv: bytes,
    sender_nostr_pub:  bytes,
    recipient_nostr_pub: bytes,
    envelope: SealedEnvelope,
) -> None:
    """
    Publish a SealedEnvelope as a Nostr kind-14 event.
    The relay sees: sender Nostr pubkey, recipient Nostr pubkey, opaque payload.
    It does NOT see the Shadow identity keys.
    """
    event = build_event(
        priv=sender_nostr_priv,
        pub=sender_nostr_pub,
        recipient_pub=recipient_nostr_pub,
        payload=envelope.serialize(),
    )
    await relay.publish(event)


def parse_sealed_from_event(event: NostrEvent) -> SealedEnvelope:
    """Decode a SealedEnvelope from a Nostr event's content field."""
    raw = decode_payload(event.content)
    return SealedEnvelope.deserialize(raw)
