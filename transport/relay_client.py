"""
Shadow — Higher-level relay client (transport/relay_client.py)

Ties together NostrRelay (WebSocket transport) and SealedSender (cryptography)
into a single convenience class.

Usage example:

    client = ShadowRelayClient(
        relay_url=DEFAULT_RELAY,
        sender=my_identity,
        nostr_priv=nostr_priv_bytes,
        nostr_pub=nostr_pub_bytes,
    )
    async with client:
        await client.send_message(
            recipient_ik_pub=contact_ik_dh_pub,
            recipient_nostr_pub=contact_nostr_pub,
            ratchet_state=state,
            plaintext=b"hello",
            AD=session_ad,
        )
        await client.receive_messages(
            my_nostr_pub=my_nostr_pub,
            handler=handle_envelope,
        )
"""

import asyncio
from typing import Callable, Awaitable

from core.identity import DeviceIdentity
from core.ratchet import RatchetState
from transport.nostr import NostrRelay, DEFAULT_RELAY
from transport.sealed_sender import (
    SealedEnvelope,
    seal_message,
    publish_sealed,
    parse_sealed_from_event,
)


class ShadowRelayClient:
    """
    High-level Shadow relay client.

    Combines NostrRelay WebSocket transport with SealedSender encryption so
    callers can send and receive encrypted Shadow messages without managing the
    underlying Nostr event structure.

    Parameters
    ----------
    relay_url    : WebSocket URL of the Nostr relay (default: wss://relay.damus.io).
    sender       : The local DeviceIdentity used to seal outgoing messages.
    nostr_priv   : 32-byte secp256k1 private key for signing Nostr events.
    nostr_pub    : 32-byte secp256k1 x-only public key (Nostr identity).
    """

    def __init__(
        self,
        relay_url: str,
        sender: DeviceIdentity,
        nostr_priv: bytes,
        nostr_pub: bytes,
    ) -> None:
        self.relay_url  = relay_url
        self.sender     = sender
        self.nostr_priv = nostr_priv
        self.nostr_pub  = nostr_pub
        self._relay: NostrRelay | None = None

    # ------------------------------------------------------------------ #
    # Context manager — connects/disconnects automatically
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> "ShadowRelayClient":
        self._relay = NostrRelay(self.relay_url)
        await self._relay.connect()
        return self

    async def __aexit__(self, *_) -> None:
        if self._relay is not None:
            await self._relay.disconnect()
            self._relay = None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def send_message(
        self,
        recipient_ik_pub: bytes,
        recipient_nostr_pub: bytes,
        ratchet_state: RatchetState,
        plaintext: bytes,
        AD: bytes,
    ) -> None:
        """
        Seal *plaintext* with the Double Ratchet + Sealed Sender and publish
        the resulting Nostr kind-14 event to the relay.

        Parameters
        ----------
        recipient_ik_pub     : 32-byte X25519 IK DH public key of the recipient
                               (used for ECIES envelope encryption).
        recipient_nostr_pub  : 32-byte secp256k1 x-only public key of the
                               recipient (used as the Nostr 'p' tag).
        ratchet_state        : Mutable Double Ratchet state; advanced in-place.
        plaintext            : Raw message bytes to encrypt.
        AD                   : Associated data bound to the session (e.g.
                               derived from both parties' identity keys).
        """
        if self._relay is None:
            raise RuntimeError(
                "ShadowRelayClient must be used as an async context manager "
                "(or connect() must be called first)."
            )

        envelope: SealedEnvelope = seal_message(
            sender=self.sender,
            recipient_ik_pub=recipient_ik_pub,
            ratchet_state=ratchet_state,
            plaintext=plaintext,
            AD=AD,
        )
        await publish_sealed(
            relay=self._relay,
            sender_nostr_priv=self.nostr_priv,
            sender_nostr_pub=self.nostr_pub,
            recipient_nostr_pub=recipient_nostr_pub,
            envelope=envelope,
        )

    async def receive_messages(
        self,
        my_nostr_pub: bytes,
        handler: Callable[[SealedEnvelope, str], Awaitable[None]],
        timeout: float = 5.0,
    ) -> None:
        """
        Subscribe to kind-14 events addressed to *my_nostr_pub*, decode each
        into a SealedEnvelope, and invoke *handler(envelope, sender_nostr_pub)*
        for every valid event received.

        The subscription runs until *timeout* seconds after the relay sends the
        EOSE (end-of-stored-events) marker, or until *timeout* seconds have
        elapsed from the start if EOSE is not received.

        Parameters
        ----------
        my_nostr_pub : 32-byte secp256k1 x-only public key we are listening on.
        handler      : Async callable ``(SealedEnvelope, sender_nostr_pub_hex)``
                       invoked for each decoded envelope.
        timeout      : Seconds to wait for new events after EOSE before closing.
        """
        if self._relay is None:
            raise RuntimeError(
                "ShadowRelayClient must be used as an async context manager "
                "(or connect() must be called first)."
            )

        relay = self._relay

        async def _on_event(event) -> None:
            # Verify BIP340 Schnorr signature before processing.
            # Without this check, a malicious relay could inject forged events.
            if not event.verify():
                return  # invalid signature — drop silently
            try:
                envelope = parse_sealed_from_event(event)
            except Exception:
                return  # malformed payload — skip
            await handler(envelope, event.pubkey)

        sub_id = await relay.subscribe_kind14(
            recipient_pub=my_nostr_pub,
            handler=_on_event,
        )

        # Wait for `timeout` seconds, then close the subscription.
        await asyncio.sleep(timeout)
        await relay.unsubscribe(sub_id)
