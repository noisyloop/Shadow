"""
Shadow — Double Ratchet Protocol
Reference: https://signal.org/docs/specifications/doubleratchet/

Primitives:
  - X25519       — Diffie-Hellman
  - HKDF-SHA256  — key derivation
  - AES-256-GCM  — AEAD encryption
  - HMAC-SHA256  — symmetric chain ratchet
"""

import os
import hmac
import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --------------------------------------------------------------------------- #
# Constants (Signal spec §2.2)
# --------------------------------------------------------------------------- #

MAX_SKIP = 1000          # maximum skipped message keys to store
HKDF_INFO_RK  = b"ShadowRootKey"
HKDF_INFO_MSG = b"ShadowMessageKey"
HMAC_CK_CONST = b"\x01"   # derive next chain key
HMAC_MK_CONST = b"\x02"   # derive message key


# --------------------------------------------------------------------------- #
# DH helpers
# All key material is stored as raw bytes (32 bytes) for serializability.
# X25519 key objects are created transiently for DH operations only.
# --------------------------------------------------------------------------- #

def generate_dh() -> tuple[bytes, bytes]:
    """Return (private_bytes, public_bytes) X25519 pair — both 32 raw bytes."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_raw  = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_raw, pub_raw


def dh(private_bytes: bytes, public_bytes: bytes) -> bytes:
    """X25519 DH: private_bytes × public_bytes → 32-byte shared secret."""
    priv = X25519PrivateKey.from_private_bytes(private_bytes)
    peer = X25519PublicKey.from_public_bytes(public_bytes)
    return priv.exchange(peer)


# --------------------------------------------------------------------------- #
# KDF functions
# --------------------------------------------------------------------------- #

def kdf_rk(root_key: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """
    KDF_RK(rk, dh_out) → (new_root_key, chain_key)
    Uses HKDF-SHA256 with the root key as salt.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=root_key,
        info=HKDF_INFO_RK,
    )
    output = hkdf.derive(dh_out)
    return output[:32], output[32:]


def kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    """
    KDF_CK(ck) → (new_chain_key, message_key)
    Uses HMAC-SHA256 with Signal spec constants 0x01 / 0x02.
    """
    new_ck = hmac.new(chain_key, HMAC_CK_CONST, hashlib.sha256).digest()
    mk     = hmac.new(chain_key, HMAC_MK_CONST, hashlib.sha256).digest()
    return new_ck, mk


# --------------------------------------------------------------------------- #
# AEAD: AES-256-GCM
# --------------------------------------------------------------------------- #

def encrypt(message_key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce || ciphertext+tag."""
    nonce = os.urandom(12)
    aead  = AESGCM(message_key)
    ct    = aead.encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def decrypt(message_key: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    """AES-256-GCM decrypt. Expects nonce || ciphertext+tag."""
    nonce = ciphertext[:12]
    ct    = ciphertext[12:]
    aead  = AESGCM(message_key)
    return aead.decrypt(nonce, ct, associated_data)


# --------------------------------------------------------------------------- #
# Message header
# --------------------------------------------------------------------------- #

@dataclass
class Header:
    dh: bytes       # sender's current ratchet public key (32 bytes)
    pn: int         # number of messages in previous sending chain
    n:  int         # message number in current sending chain

    def serialize(self) -> bytes:
        """32-byte DH key || 4-byte PN || 4-byte N (big-endian)."""
        return self.dh + struct.pack(">II", self.pn, self.n)

    @classmethod
    def deserialize(cls, data: bytes) -> "Header":
        if len(data) < 40:
            raise ValueError(f"Header too short: {len(data)} bytes (need 40)")
        dh = data[:32]
        pn, n = struct.unpack(">II", data[32:40])
        return cls(dh=dh, pn=pn, n=n)

    def __len__(self):
        return 40


def concat_ad(associated_data: bytes, header: Header) -> bytes:
    """Bind the header to the associated data so it is authenticated."""
    hdr_bytes = header.serialize()
    return associated_data + struct.pack(">I", len(hdr_bytes)) + hdr_bytes


# --------------------------------------------------------------------------- #
# Double Ratchet state
# All byte fields are plain bytes so the state is fully copyable / serializable.
# --------------------------------------------------------------------------- #

@dataclass
class RatchetState:
    DHs:       tuple                    # (private_bytes, public_bytes) — 32 raw bytes each
    DHr:       Optional[bytes]          # their current ratchet public key (32 raw bytes)
    RK:        bytes                    # 32-byte root key
    CKs:       Optional[bytes]          # sending chain key
    CKr:       Optional[bytes]          # receiving chain key
    Ns:        int = 0                  # sending message counter
    Nr:        int = 0                  # receiving message counter
    PN:        int = 0                  # previous chain message count
    MKSKIPPED: dict = field(default_factory=dict)  # {(dh_pub, n): message_key}


# --------------------------------------------------------------------------- #
# Ratchet initialisation (Signal spec §3.3)
# --------------------------------------------------------------------------- #

def ratchet_init_alice(SK: bytes, bob_dh_public: bytes) -> RatchetState:
    """
    Alice initialises after X3DH.
    SK             — shared secret from X3DH
    bob_dh_public  — Bob's signed prekey public bytes (initial ratchet key)
    """
    dhs_priv, dhs_pub = generate_dh()
    rk, cks = kdf_rk(SK, dh(dhs_priv, bob_dh_public))
    return RatchetState(
        DHs=(dhs_priv, dhs_pub),
        DHr=bob_dh_public,
        RK=rk,
        CKs=cks,
        CKr=None,
    )


def ratchet_init_bob(SK: bytes, bob_dh_pair: tuple) -> RatchetState:
    """
    Bob initialises after X3DH.
    SK           — shared secret from X3DH
    bob_dh_pair  — (private_bytes, public_bytes) Bob's signed prekey pair
    """
    return RatchetState(
        DHs=bob_dh_pair,
        DHr=None,
        RK=SK,
        CKs=None,
        CKr=None,
    )


# --------------------------------------------------------------------------- #
# Encrypt (Signal spec §3.4)
# --------------------------------------------------------------------------- #

def ratchet_encrypt(state: RatchetState, plaintext: bytes, AD: bytes) -> tuple[Header, bytes]:
    """
    Encrypt plaintext using state.
    Returns (header, ciphertext).
    Advances the sending chain.
    """
    state.CKs, mk = kdf_ck(state.CKs)
    header = Header(dh=state.DHs[1], pn=state.PN, n=state.Ns)
    state.Ns += 1
    ct = encrypt(mk, plaintext, concat_ad(AD, header))
    return header, ct


# --------------------------------------------------------------------------- #
# Decrypt helpers (Signal spec §3.5)
# --------------------------------------------------------------------------- #

def _try_skipped_message_keys(
    state: RatchetState,
    header: Header,
    ciphertext: bytes,
    AD: bytes,
) -> Optional[bytes]:
    key = (bytes(header.dh), header.n)
    if key in state.MKSKIPPED:
        mk = state.MKSKIPPED.pop(key)
        return decrypt(mk, ciphertext, concat_ad(AD, header))
    return None


def _skip_message_keys(state: RatchetState, until: int) -> None:
    if state.Nr + MAX_SKIP < until:
        raise ValueError(f"Too many skipped messages: {until - state.Nr}")
    if state.CKr is not None:
        while state.Nr < until:
            state.CKr, mk = kdf_ck(state.CKr)
            state.MKSKIPPED[(bytes(state.DHr), state.Nr)] = mk
            state.Nr += 1


def _dh_ratchet(state: RatchetState, header: Header) -> None:
    """Perform a DH ratchet step on receipt of a new sender ratchet key."""
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = kdf_rk(state.RK, dh(state.DHs[0], state.DHr))
    state.DHs = generate_dh()
    state.RK, state.CKs = kdf_rk(state.RK, dh(state.DHs[0], state.DHr))


def ratchet_decrypt(state: RatchetState, header: Header, ciphertext: bytes, AD: bytes) -> bytes:
    """
    Decrypt a received message.
    Handles out-of-order delivery via skipped message key store.
    """
    # 1. Check skipped keys first
    plaintext = _try_skipped_message_keys(state, header, ciphertext, AD)
    if plaintext is not None:
        return plaintext

    # 2. DH ratchet step if sender has rotated their key
    if state.DHr is None or bytes(header.dh) != bytes(state.DHr):
        _skip_message_keys(state, header.pn)
        _dh_ratchet(state, header)

    # 3. Skip within current chain (out-of-order)
    _skip_message_keys(state, header.n)

    # 4. Decrypt
    state.CKr, mk = kdf_ck(state.CKr)
    state.Nr += 1
    return decrypt(mk, ciphertext, concat_ad(AD, header))
