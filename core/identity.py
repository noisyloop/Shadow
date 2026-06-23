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
    identity_key:        bytes          # IK DH public (X25519, 32 bytes)
    identity_sign_key:   bytes          # IK signing public (ed25519, 32 bytes)
    spk_id:              int
    spk_public:          bytes          # SPK public (X25519, 32 bytes)
    spk_signature:       bytes          # ed25519 sig of spk_public by IK signing key
    opk_id:              Optional[int]  # OPK id, or None
    opk_public:          Optional[bytes]  # OPK public (X25519, 32 bytes), or None
    needs_replenishment: bool = False   # True when pool drops below OPK_LOW_WATER_MARK

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
        required = ("identity_key", "identity_sign_key", "spk_id",
                    "spk_public", "spk_signature")
        for field_name in required:
            if field_name not in d:
                raise ValueError(f"PreKeyBundle JSON missing required field: {field_name}")
        opk_public_raw = d.get("opk_public")
        return cls(
            identity_key=bytes.fromhex(d["identity_key"]),
            identity_sign_key=bytes.fromhex(d["identity_sign_key"]),
            spk_id=d["spk_id"],
            spk_public=bytes.fromhex(d["spk_public"]),
            spk_signature=bytes.fromhex(d["spk_signature"]),
            opk_id=d.get("opk_id"),
            opk_public=bytes.fromhex(opk_public_raw) if opk_public_raw else None,
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
# OPK batch generation helper
# --------------------------------------------------------------------------- #

def generate_opk_batch(
    identity: DeviceIdentity,
    count: int = 10,
    existing_opks: Optional[list[OneTimePreKey]] = None,
) -> list[OneTimePreKey]:
    """
    Generate a batch of fresh OPKs for replenishment.

    IDs are assigned sequentially starting after the highest ID already present
    in ``existing_opks`` (or from 0 if none are provided).

    The caller is responsible for publishing the returned OPKs to the prekey
    server via ``PrekeyServer.replenish_opks()``.
    """
    if existing_opks:
        start_id = max(opk.id for opk in existing_opks) + 1
    else:
        start_id = 0
    return identity.generate_opks(count, start_id=start_id)


# --------------------------------------------------------------------------- #
# Prekey server stub
# --------------------------------------------------------------------------- #

class PrekeyServer:
    """
    In-memory prekey server stub.
    In production this would be an HTTP API backed by a database.
    """

    OPK_LOW_WATER_MARK  = 5   # replenishment needed when pool falls below this
    OPK_REPLENISH_BATCH = 10  # default batch size for replenishment

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
        Sets needs_replenishment=True when the remaining pool size drops below
        OPK_LOW_WATER_MARK.
        """
        key = identity_key.hex()
        bundle = self._bundles.get(key)
        if bundle is None:
            return None
        # Attach a fresh OPK from the pool, if any remain
        pool = self._opk_pool.get(key, [])
        if pool:
            opk_id, opk_pub = pool.pop(0)
            needs_replenishment = len(pool) < self.OPK_LOW_WATER_MARK
            bundle = PreKeyBundle(
                identity_key=bundle.identity_key,
                identity_sign_key=bundle.identity_sign_key,
                spk_id=bundle.spk_id,
                spk_public=bundle.spk_public,
                spk_signature=bundle.spk_signature,
                opk_id=opk_id,
                opk_public=opk_pub,
                needs_replenishment=needs_replenishment,
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
                needs_replenishment=True,
            )
        return bundle

    def opk_count(self, ik_pub_hex: str) -> int:
        """Return current OPK pool size for an identity key (hex string)."""
        return len(self._opk_pool.get(ik_pub_hex, []))

    def replenish_opks(
        self,
        ik_pub_hex: str,
        new_opks: list[tuple[int, bytes]],
    ) -> None:
        """Append new OPKs to the pool for a given identity key (hex string)."""
        pool = self._opk_pool.setdefault(ik_pub_hex, [])
        pool.extend(new_opks)


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
