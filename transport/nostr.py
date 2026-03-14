"""
Shadow — Nostr Transport Layer
Reference: https://github.com/nostr-protocol/nostr

Uses Nostr relays as the message transport. Messages are published as
encrypted Nostr events (kind 14 — sealed DM). No server to run, no cost,
already federated.

Nostr event structure:
  {
    "id":         <sha256 of canonical serialization>,
    "pubkey":     <hex of 32-byte x-only secp256k1 public key>,
    "created_at": <unix timestamp>,
    "kind":       14,
    "tags":       [["p", "<recipient pubkey hex>"]],
    "content":    "<base64-encoded Shadow envelope>",
    "sig":        <BIP340 Schnorr signature>
  }

Crypto:
  - secp256k1 x-only pubkeys (Nostr identity is separate from Shadow identity)
  - BIP340 Schnorr signatures (event authentication)
  - Shadow handles message encryption via Double Ratchet + Sealed Sender

Note: Nostr keypairs are used only for relay-level event authentication.
      Shadow's cryptographic identity lives in core/identity.py.
"""

import os
import json
import time
import asyncio
import hashlib
import hmac as hmac_mod
import base64
import struct
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

import websockets
from websockets.exceptions import ConnectionClosed


# --------------------------------------------------------------------------- #
# BIP340 Schnorr on secp256k1 (pure Python)
# Reference: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
# --------------------------------------------------------------------------- #

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if y1 != y2: return None
        lam = 3 * x1 * x1 * pow(2 * y1, _P - 2, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, _P - 2, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return x3, y3


def _point_mul(P, n):
    R, Q = None, P
    while n:
        if n & 1: R = _point_add(R, Q)
        Q = _point_add(Q, Q)
        n >>= 1
    return R


def _lift_x(x: int):
    """Lift an x coordinate to the curve point with even y."""
    y_sq = (pow(x, 3, _P) + 7) % _P
    y    = pow(y_sq, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else _P - y)


def _tagged_hash(tag: bytes, msg: bytes) -> bytes:
    t = hashlib.sha256(tag).digest()
    return hashlib.sha256(t + t + msg).digest()


def schnorr_keygen() -> tuple[bytes, bytes]:
    """
    Generate a secp256k1 Nostr keypair.
    Returns (private_key_bytes, public_key_bytes) — both 32 raw bytes.
    Public key is the x-only encoding (BIP340).
    """
    while True:
        priv_int = int.from_bytes(os.urandom(32), "big")
        if 1 <= priv_int < _N:
            P = _point_mul(_G, priv_int)
            # Normalise: private key corresponds to even-y public key
            if P[1] % 2 != 0:
                priv_int = _N - priv_int
                P = _point_mul(_G, priv_int)
            priv = priv_int.to_bytes(32, "big")
            pub  = P[0].to_bytes(32, "big")
            return priv, pub


def schnorr_sign(msg32: bytes, priv: bytes) -> bytes:
    """BIP340 Schnorr sign. msg32 must be exactly 32 bytes."""
    assert len(msg32) == 32
    d0 = int.from_bytes(priv, "big")
    assert 1 <= d0 < _N
    P  = _point_mul(_G, d0)
    d  = d0 if P[1] % 2 == 0 else _N - d0
    P_bytes = P[0].to_bytes(32, "big")

    aux   = os.urandom(32)
    t     = d ^ int.from_bytes(_tagged_hash(b"BIP0340/aux", aux), "big")
    k0    = int.from_bytes(
        _tagged_hash(b"BIP0340/nonce", t.to_bytes(32, "big") + P_bytes + msg32), "big"
    ) % _N
    assert k0 != 0

    R  = _point_mul(_G, k0)
    k  = k0 if R[1] % 2 == 0 else _N - k0
    e  = int.from_bytes(
        _tagged_hash(b"BIP0340/challenge", R[0].to_bytes(32, "big") + P_bytes + msg32), "big"
    ) % _N
    return R[0].to_bytes(32, "big") + ((k + e * d) % _N).to_bytes(32, "big")


def schnorr_verify(msg32: bytes, pub: bytes, sig: bytes) -> bool:
    """BIP340 Schnorr verify."""
    if len(msg32) != 32 or len(pub) != 32 or len(sig) != 64:
        return False
    P = _lift_x(int.from_bytes(pub, "big"))
    if P is None:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if r >= _P or s >= _N:
        return False
    e = int.from_bytes(
        _tagged_hash(b"BIP0340/challenge", sig[:32] + pub + msg32), "big"
    ) % _N
    R = _point_add(_point_mul(_G, s), _point_mul(P, _N - e))
    if R is None or R[1] % 2 != 0 or R[0] != r:
        return False
    return True


# --------------------------------------------------------------------------- #
# Nostr event
# --------------------------------------------------------------------------- #

SHADOW_KIND = 14   # NIP-17 sealed DM


@dataclass
class NostrEvent:
    pubkey:     str          # hex-encoded x-only secp256k1 public key
    created_at: int          # unix timestamp
    kind:       int          # event kind
    tags:       list         # list of tag lists
    content:    str          # encrypted Shadow envelope (base64)
    id:         str = ""     # sha256 of canonical form (computed on sign)
    sig:        str = ""     # BIP340 Schnorr signature (computed on sign)

    def canonical(self) -> bytes:
        """Canonical serialization for signing / id computation."""
        return json.dumps(
            [0, self.pubkey, self.created_at, self.kind, self.tags, self.content],
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def compute_id(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()

    def sign(self, priv: bytes) -> "NostrEvent":
        """Sign the event with a secp256k1 private key. Returns self."""
        self.id  = self.compute_id()
        msg32    = bytes.fromhex(self.id)
        self.sig = schnorr_sign(msg32, priv).hex()
        return self

    def verify(self) -> bool:
        """Verify the event id and signature."""
        if self.compute_id() != self.id:
            return False
        return schnorr_verify(bytes.fromhex(self.id), bytes.fromhex(self.pubkey), bytes.fromhex(self.sig))

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "pubkey":     self.pubkey,
            "created_at": self.created_at,
            "kind":       self.kind,
            "tags":       self.tags,
            "content":    self.content,
            "sig":        self.sig,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "NostrEvent":
        e = cls(
            pubkey=d["pubkey"],
            created_at=d["created_at"],
            kind=d["kind"],
            tags=d["tags"],
            content=d["content"],
        )
        e.id  = d.get("id", "")
        e.sig = d.get("sig", "")
        return e


def build_event(
    priv: bytes,
    pub:  bytes,
    recipient_pub: bytes,
    payload: bytes,
) -> NostrEvent:
    """
    Build a signed Nostr kind-14 event.

    payload — raw bytes of the Shadow sealed envelope.
               Base64-encoded as the event content.
    recipient_pub — 32-byte secp256k1 x-only pubkey of recipient (for tagging).
    """
    event = NostrEvent(
        pubkey=pub.hex(),
        created_at=int(time.time()),
        kind=SHADOW_KIND,
        tags=[["p", recipient_pub.hex()]],
        content=base64.b64encode(payload).decode(),
    )
    event.sign(priv)
    return event


# --------------------------------------------------------------------------- #
# Nostr relay client
# --------------------------------------------------------------------------- #

class NostrRelay:
    """
    Async Nostr relay WebSocket client.

    Usage:
        relay = NostrRelay("wss://relay.damus.io")
        async with relay:
            await relay.publish(event)
            async for event in relay.subscribe(filter):
                handle(event)
    """

    def __init__(self, url: str):
        self.url = url
        self._ws  = None
        self._sub_handlers: dict[str, Callable] = {}
        self._recv_task = None

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *_):
        await self.disconnect()

    async def connect(self) -> None:
        self._ws = await websockets.connect(self.url)
        self._recv_task = asyncio.create_task(self._recv_loop())

    async def disconnect(self) -> None:
        if self._recv_task:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass
        if self._ws:
            await self._ws.close()

    async def publish(self, event: NostrEvent) -> None:
        """Publish an event to the relay."""
        msg = json.dumps(["EVENT", event.to_dict()])
        await self._ws.send(msg)

    async def subscribe(
        self,
        sub_id: str,
        filters: dict,
        handler: Callable[[NostrEvent], Awaitable[None]],
    ) -> None:
        """
        Subscribe to events matching filters.
        handler is called for each matching event.
        """
        self._sub_handlers[sub_id] = handler
        msg = json.dumps(["REQ", sub_id, filters])
        await self._ws.send(msg)

    async def unsubscribe(self, sub_id: str) -> None:
        self._sub_handlers.pop(sub_id, None)
        msg = json.dumps(["CLOSE", sub_id])
        await self._ws.send(msg)

    async def _recv_loop(self) -> None:
        """Background task: dispatch incoming relay messages."""
        try:
            async for raw in self._ws:
                try:
                    msg = json.loads(raw)
                    if not isinstance(msg, list) or len(msg) < 2:
                        continue
                    msg_type = msg[0]
                    if msg_type == "EVENT" and len(msg) >= 3:
                        sub_id = msg[1]
                        event  = NostrEvent.from_dict(msg[2])
                        handler = self._sub_handlers.get(sub_id)
                        if handler and event.verify():
                            await handler(event)
                    elif msg_type == "NOTICE":
                        pass  # relay notice — could log
                    elif msg_type == "OK":
                        pass  # publish acknowledgement
                except (json.JSONDecodeError, KeyError):
                    continue
        except ConnectionClosed:
            pass


# --------------------------------------------------------------------------- #
# Shadow message helpers for Nostr
# --------------------------------------------------------------------------- #

def encode_payload(envelope_bytes: bytes) -> str:
    """Encode a Shadow envelope as base64 for Nostr content field."""
    return base64.b64encode(envelope_bytes).decode()


def decode_payload(content: str) -> bytes:
    """Decode the base64 Nostr content field back to raw envelope bytes."""
    return base64.b64decode(content)


# --------------------------------------------------------------------------- #
# Local relay stub (for testing without a real Nostr relay)
# --------------------------------------------------------------------------- #

class LocalRelay:
    """
    In-process relay stub for unit and integration tests.
    Implements the same interface as NostrRelay without network I/O.
    """

    def __init__(self):
        self._inbox: dict[str, list[NostrEvent]] = {}   # pubkey_hex -> events
        self._sub_handlers: dict[str, tuple[dict, Callable]] = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    async def publish(self, event: NostrEvent) -> None:
        """Store event; route to any matching subscription handlers."""
        if not event.verify():
            return
        # Route to recipient inboxes via 'p' tags
        for tag in event.tags:
            if tag[0] == "p":
                inbox = self._inbox.setdefault(tag[1], [])
                inbox.append(event)
        # Dispatch to live subscribers
        for sub_id, (filters, handler) in list(self._sub_handlers.items()):
            if self._matches(event, filters):
                await handler(event)

    async def subscribe(
        self,
        sub_id: str,
        filters: dict,
        handler: Callable[[NostrEvent], Awaitable[None]],
    ) -> None:
        self._sub_handlers[sub_id] = (filters, handler)
        # Deliver any already-queued events that match
        pubkey = filters.get("authors", [None])[0]
        if pubkey and pubkey in self._inbox:
            for event in list(self._inbox[pubkey]):
                if self._matches(event, filters):
                    await handler(event)

    async def unsubscribe(self, sub_id: str) -> None:
        self._sub_handlers.pop(sub_id, None)

    def inbox(self, pubkey_hex: str) -> list[NostrEvent]:
        """Return all queued events for a recipient pubkey."""
        return self._inbox.get(pubkey_hex, [])

    @staticmethod
    def _matches(event: NostrEvent, filters: dict) -> bool:
        if "kinds" in filters and event.kind not in filters["kinds"]:
            return False
        if "#p" in filters:
            tagged = {tag[1] for tag in event.tags if tag[0] == "p"}
            if not any(p in tagged for p in filters["#p"]):
                return False
        return True
