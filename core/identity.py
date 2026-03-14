"""
Shadow — Device Identity and Prekey Infrastructure

Provides:
  - DeviceIdentity   — long-term device keypair (X25519 DH + ed25519 signing)
  - SignedPreKey      — medium-term DH key, signed by the identity key
  - OneTimePreKey     — ephemeral DH key, consumed once per session
  - PreKeyBundle      — public bundle published to the prekey server
  - PrekeyServer      — in-memory prekey server stub
"""

import os
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.exceptions import InvalidSignature

from .ratchet import generate_dh


# --------------------------------------------------------------------------- #
# Key types
# --------------------------------------------------------------------------- #

@dataclass
class SignedPreKey:
    """Medium-term X25519 keypair, signed by the identity key. Rotate weekly."""
    id:        int
    priv:      bytes   # 32 raw bytes
    pub:       bytes   # 32 raw bytes
    signature: bytes   # 64-byte ed25519 sig of pub by IK signing key


@dataclass
class OneTimePreKey:
    """Ephemeral X25519 keypair. Consumed once, never reused."""
    id:   int
    priv: bytes   # 32 raw bytes
    pub:  bytes   # 32 raw bytes


@dataclass
class PreKeyBundle:
    """Bob's public key bundle published to the prekey server."""
    identity_key:      bytes          # IK DH public (X25519, 32 bytes)
    identity_sign_key: bytes          # IK signing public (ed25519, 32 bytes)
    spk_id:            int
    spk_public:        bytes          # SPK public (X25519, 32 bytes)
    spk_signature:     bytes          # ed25519 sig of spk_public by IK signing key
    opk_id:            Optional[int]  # OPK id, or None
    opk_public:        Optional[bytes]  # OPK public (X25519, 32 bytes), or None

    def to_json(self) -> str:
        d = {
            "identity_key":      self.identity_key.hex(),
            "identity_sign_key": self.identity_sign_key.hex(),
            "spk_id":            self.spk_id,
            "spk_public":        self.spk_public.hex(),
            "spk_signature":     self.spk_signature.hex(),
            "opk_id":            self.opk_id,
            "opk_public":        self.opk_public.hex() if self.opk_public else None,
        }
        return json.dumps(d)

    @classmethod
    def from_json(cls, s: str) -> "PreKeyBundle":
        d = json.loads(s)
        return cls(
            identity_key=bytes.fromhex(d["identity_key"]),
            identity_sign_key=bytes.fromhex(d["identity_sign_key"]),
            spk_id=d["spk_id"],
            spk_public=bytes.fromhex(d["spk_public"]),
            spk_signature=bytes.fromhex(d["spk_signature"]),
            opk_id=d["opk_id"],
            opk_public=bytes.fromhex(d["opk_public"]) if d["opk_public"] else None,
        )


# --------------------------------------------------------------------------- #
# Device identity
# --------------------------------------------------------------------------- #

@dataclass
class DeviceIdentity:
    """
    Full device identity — private keys never leave the device.

    ik_dh_*   — X25519 keypair used in X3DH DH computations
    ik_sign_* — ed25519 keypair used to sign the SPK (proves SPK ownership)
    """
    ik_dh_priv:   bytes   # 32 raw bytes
    ik_dh_pub:    bytes   # 32 raw bytes
    ik_sign_priv: bytes   # 32-byte ed25519 seed
    ik_sign_pub:  bytes   # 32 raw bytes

    @classmethod
    def generate(cls) -> "DeviceIdentity":
        dh_priv_obj  = X25519PrivateKey.generate()
        sgn_priv_obj = Ed25519PrivateKey.generate()
        return cls(
            ik_dh_priv=dh_priv_obj.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            ),
            ik_dh_pub=dh_priv_obj.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ),
            ik_sign_priv=sgn_priv_obj.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            ),
            ik_sign_pub=sgn_priv_obj.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ),
        )

    def sign(self, data: bytes) -> bytes:
        """Sign data with the ed25519 identity signing key."""
        priv = Ed25519PrivateKey.from_private_bytes(self.ik_sign_priv)
        return priv.sign(data)

    def generate_spk(self, spk_id: int) -> SignedPreKey:
        """Generate a new signed prekey, signed by this identity."""
        priv, pub = generate_dh()
        sig = self.sign(pub)
        return SignedPreKey(id=spk_id, priv=priv, pub=pub, signature=sig)

    def generate_opks(self, count: int, start_id: int = 0) -> list[OneTimePreKey]:
        """Generate a batch of one-time prekeys."""
        opks = []
        for i in range(count):
            priv, pub = generate_dh()
            opks.append(OneTimePreKey(id=start_id + i, priv=priv, pub=pub))
        return opks

    def build_bundle(
        self,
        spk: SignedPreKey,
        opk: Optional[OneTimePreKey] = None,
    ) -> PreKeyBundle:
        """Assemble the public prekey bundle for publication."""
        return PreKeyBundle(
            identity_key=self.ik_dh_pub,
            identity_sign_key=self.ik_sign_pub,
            spk_id=spk.id,
            spk_public=spk.pub,
            spk_signature=spk.signature,
            opk_id=opk.id if opk else None,
            opk_public=opk.pub if opk else None,
        )


# --------------------------------------------------------------------------- #
# Prekey server stub
# --------------------------------------------------------------------------- #

class PrekeyServer:
    """
    In-memory prekey server stub.
    In production this would be an HTTP API backed by a database.
    """

    def __init__(self):
        # identity_key_hex -> PreKeyBundle
        self._bundles: dict[str, PreKeyBundle] = {}
        # identity_key_hex -> list of OneTimePreKey (server only stores pub+id)
        self._opk_pool: dict[str, list[tuple[int, bytes]]] = {}

    def publish(
        self,
        bundle: PreKeyBundle,
        extra_opks: Optional[list[OneTimePreKey]] = None,
    ) -> None:
        """
        Publish or refresh a prekey bundle.
        Any OPK attached to the bundle and any extra_opks are added to the pool.
        The stored bundle itself has opk_id/opk_public stripped — the server
        always attaches a fresh OPK from the pool on each fetch.
        """
        key = bundle.identity_key.hex()
        # Strip OPK from the stored bundle; pool manages OPKs
        stored = PreKeyBundle(
            identity_key=bundle.identity_key,
            identity_sign_key=bundle.identity_sign_key,
            spk_id=bundle.spk_id,
            spk_public=bundle.spk_public,
            spk_signature=bundle.spk_signature,
            opk_id=None,
            opk_public=None,
        )
        self._bundles[key] = stored
        pool = self._opk_pool.setdefault(key, [])
        # Add bundle's inline OPK to pool
        if bundle.opk_id is not None and bundle.opk_public is not None:
            pool.append((bundle.opk_id, bundle.opk_public))
        # Add any extra OPKs
        if extra_opks:
            for opk in extra_opks:
                pool.append((opk.id, opk.pub))

    def fetch(self, identity_key: bytes) -> Optional[PreKeyBundle]:
        """
        Fetch the bundle for a recipient.
        Pops one OPK from the pool if available and attaches it to the bundle.
        """
        key = identity_key.hex()
        bundle = self._bundles.get(key)
        if bundle is None:
            return None
        # Attach a fresh OPK from the pool, if any remain
        pool = self._opk_pool.get(key, [])
        if pool:
            opk_id, opk_pub = pool.pop(0)
            bundle = PreKeyBundle(
                identity_key=bundle.identity_key,
                identity_sign_key=bundle.identity_sign_key,
                spk_id=bundle.spk_id,
                spk_public=bundle.spk_public,
                spk_signature=bundle.spk_signature,
                opk_id=opk_id,
                opk_public=opk_pub,
            )
        else:
            # Graceful degradation: no OPK available
            bundle = PreKeyBundle(
                identity_key=bundle.identity_key,
                identity_sign_key=bundle.identity_sign_key,
                spk_id=bundle.spk_id,
                spk_public=bundle.spk_public,
                spk_signature=bundle.spk_signature,
                opk_id=None,
                opk_public=None,
            )
        return bundle

    def opk_count(self, identity_key: bytes) -> int:
        return len(self._opk_pool.get(identity_key.hex(), []))


# --------------------------------------------------------------------------- #
# Bundle verification (used by Alice before initiating X3DH)
# --------------------------------------------------------------------------- #

def verify_bundle(bundle: PreKeyBundle) -> None:
    """
    Verify the SPK signature in a prekey bundle.
    Raises cryptography.exceptions.InvalidSignature on failure.
    """
    pub = Ed25519PublicKey.from_public_bytes(bundle.identity_sign_key)
    pub.verify(bundle.spk_signature, bundle.spk_public)
