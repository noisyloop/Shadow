# Shadow

> End-to-end encrypted communications. No phone number. No central identity authority.

Shadow is an open-source, research-grade encrypted messaging protocol and application. It implements the Signal Double Ratchet and X3DH handshake from scratch, with a focus on auditability, minimal dependencies, and a privacy model that does not require a phone number or any KYC-linked identifier to participate.

This is both a research project and a real application. The protocol is designed to be readable — someone with a cryptography background should be able to audit the full implementation in an afternoon.

---

## Why

Phone numbers are a legal handle, not a technical requirement. Every major encrypted messenger ties identity to a phone number, which is a government-accessible identifier by design. Shadow uses a device-generated keypair as the sole identity primitive. No registration. No account. No number.

This is also a response to ongoing 0-day vulnerabilities affecting encryption implementations, and to platforms removing end-to-end encryption from features that previously had it. Shadow is open source, auditable, and the encryption is the product — not a checkbox.

---

## Protocol overview

Shadow implements two interlocking cryptographic systems:

**X3DH (Extended Triple Diffie-Hellman)** — the initial handshake. Establishes a shared secret between two parties asynchronously. Bob does not need to be online when Alice initiates. Uses identity keys, signed prekeys, and one-time prekeys.

**Double Ratchet** — the ongoing session encryption. Every message is encrypted with a unique key derived from two ratchets running in parallel: a Diffie-Hellman ratchet that rotates the root key on each reply, and a symmetric ratchet that derives per-message keys from chain keys.

**Sealed Sender** — hides the sender's identity from the relay. The relay sees only an opaque blob addressed to a key hint. The sender certificate is encrypted inside the ECIES envelope and visible only to the recipient.

**Nostr transport** — messages are published as kind-14 encrypted events to public Nostr relays. No server to run, no registration, no cost.

Properties:
- Forward secrecy — past messages are safe even if current keys are compromised
- Break-in recovery — future messages are re-secured after the next DH ratchet step
- Message key independence — each message uses a unique key
- Out-of-order delivery — skipped message keys are stored and used when late messages arrive
- Sealed sender — relay cannot determine who is messaging whom
- OPK replenishment — one-time prekey pool auto-refills when it falls below threshold

Primitives: X25519 (DH), HKDF-SHA256 (key derivation), AES-256-GCM (AEAD), HMAC-SHA256 (chain ratchet), Ed25519 (identity signing).

---

## Repository structure

```
Shadow/
├── core/                        # Python reference implementation (Phases 0–1)
│   ├── ratchet.py               # Double Ratchet — KDF_RK, KDF_CK, encrypt, decrypt
│   ├── x3dh.py                  # X3DH send/receive, InitialMessage wire format
│   └── identity.py              # DeviceIdentity, SPK, OPK, PrekeyServer
├── transport/                   # Network / relay layer (Phases 2–3)
│   ├── nostr.py                 # BIP340 Schnorr, NostrEvent, NostrRelay, LocalRelay
│   ├── sealed_sender.py         # ECIES envelope, SenderCertificate, seal/unseal
│   └── relay_client.py          # ShadowRelayClient — high-level send/receive over Nostr
├── tests/
│   ├── test_ratchet.py          # 8 tests — all Double Ratchet properties
│   ├── test_x3dh.py             # 5 tests — X3DH handshake + OPK replenishment
│   └── test_integration.py      # 6 tests — sealed sender + Nostr round-trip
├── cli/                         # Rust CLI/TUI (Phase 4)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs              # clap CLI: init, add, send, recv, key
│       ├── commands/            # init, add, key, send (Nostr-wired), recv (Nostr-wired)
│       ├── crypto/              # ratchet.rs, identity.rs, x3dh.rs
│       ├── transport/           # nostr.rs (tokio-tungstenite WebSocket)
│       ├── tui/                 # app.rs, ui.rs (ratatui TUI)
│       └── store.rs             # ~/.shadow/ JSON persistence
├── mobile/                      # React Native / Expo app (Phase 5)
│   ├── App.tsx
│   ├── package.json
│   └── src/
│       ├── crypto/              # identity.ts, ratchet.ts, x3dh.ts (@noble)
│       ├── store/               # keys.ts, messages.ts, contacts.ts (zustand)
│       ├── transport/           # nostr.ts (WebSocket Nostr client, auto-reconnect)
│       ├── screens/             # Home, Chat, AddContact, Key, Verify
│       ├── components/          # MessageBubble, QRDisplay
│       └── navigation/          # index.tsx
└── docs/
    ├── PROTOCOL.md              # Full cryptographic protocol specification
    └── THREAT_MODEL.md          # Trust model, threat actors, known weaknesses
```

---

## Status

### Phase 0 — Double Ratchet ✅
**Complete. 8/8 tests passing.**

- [x] X25519 DH key exchange
- [x] HKDF-SHA256 root and chain key derivation
- [x] AES-256-GCM AEAD with random 12-byte nonce
- [x] HMAC-SHA256 symmetric chain ratchet (`0x01` / `0x02` constants, Signal spec)
- [x] DH ratchet step on new sender key
- [x] Skipped message key store (up to 1000 keys)
- [x] Forward secrecy, break-in recovery, out-of-order delivery, AD binding, header integrity

---

### Phase 1 — X3DH Handshake ✅
**Complete. 5/5 tests passing.**

- [x] DeviceIdentity — X25519 DH keypair + Ed25519 signing keypair
- [x] SignedPreKey — medium-term X25519, signed by IK, rotatable
- [x] OneTimePrekeys — ephemeral X25519, consumed once per session
- [x] X3DH sender (Alice): verify SPK sig, EK generation, DH1–DH4, SK derivation
- [x] X3DH receiver (Bob): mirror DH ops, init ratchet, decrypt initial message
- [x] Graceful degradation when no OPK available (3-DH fallback)
- [x] OPK consumed and never reused
- [x] OPK replenishment — pool auto-refills below low-water mark (5 keys)
- [x] PreKeyBundle serialization (binary + JSON)
- [x] PrekeyServer stub with `needs_replenishment` signal

---

### Phase 2 — Nostr Transport ✅
**Complete. Wired to `wss://relay.damus.io` by default.**

- [x] BIP340 Schnorr signatures on secp256k1 (pure Python)
- [x] NostrEvent canonical serialization and signing
- [x] NostrRelay async WebSocket client — publish and subscribe
- [x] LocalRelay in-process stub for testing
- [x] `subscribe_kind14()` — kind-14 sealed DM subscription
- [x] `ShadowRelayClient` — high-level send/receive combining Nostr + SealedSender
- [x] CLI `send --relay <url>` publishes to Nostr relay
- [x] CLI `recv --relay <url> --timeout <s>` polls for new messages
- [x] Mobile `transport/nostr.ts` — React Native WebSocket client with auto-reconnect

---

### Phase 3 — Sealed Sender ✅
**Complete. 6/6 integration tests passing.**

- [x] ECIES envelope — ephemeral X25519 + HKDF-SHA256 + AES-256-GCM
- [x] `eph_pub` bound as AEAD associated data (tampering detected)
- [x] SenderCertificate — short-lived Ed25519-signed credential (24h TTL)
- [x] `recipient_key_hint` — first 8 bytes of recipient IK pub (routing only)
- [x] `seal_message` / `unseal_message` public API
- [x] Nostr event integration — envelope published as kind-14 event
- [x] Relay sees no sender identity in plaintext
- [x] Tampered envelope rejected, expired certificate rejected

---

### Phase 4 — Rust CLI/TUI ✅
**Complete. Builds clean (ratatui 0.30, crossterm 0.29, tokio-tungstenite 0.24).**

```
shadow init                  # Generate device identity keypair
shadow add <name> <pubkey>   # Add a contact by public key
shadow send <contact> -m "…" # Send a message (--relay to specify relay)
shadow recv                  # Poll for messages (--relay, --timeout)
shadow key show              # Display identity key + QR code
shadow key rotate            # Rotate signed prekey
```

- [x] Double Ratchet, X3DH, identity ported to Rust (`x25519-dalek`, `ed25519-dalek`, `aes-gcm`)
- [x] `~/.shadow/` JSON store — identity, contacts, sessions, messages
- [x] ratatui TUI for interactive messaging sessions
- [x] Nostr WebSocket transport (`tokio-tungstenite`)
- [x] `send` publishes sealed messages to Nostr relay
- [x] `recv` subscribes to kind-14 events, decrypts, stores

---

### Phase 5 — Mobile App ✅
**Complete. React Native / Expo scaffold.**

- [x] Crypto layer: `@noble/curves` (X25519, Ed25519), `@noble/hashes` (HKDF, HMAC), SubtleCrypto (AES-256-GCM)
- [x] Zustand stores with `expo-secure-store` persistence
- [x] HomeScreen — contact list with verified ✓ badges
- [x] ChatScreen — E2E encrypted thread, shield icon header button for key verification
- [x] AddContactScreen — QR scanner (`shadow://key/<hex>`) + manual hex paste
- [x] KeyScreen — QR display of own identity key, SPK metadata, copy/share
- [x] **VerifyScreen** — side-by-side QR display of both keys, "Mark as Verified" / "Remove Verification", orange out-of-band verification warning
- [x] OPK auto-replenishment — `consumeOpk()` triggers `replenishOpks(10)` when pool < 5
- [x] `transport/nostr.ts` — WebSocket Nostr client, pub/sub, EOSE handling, exponential backoff reconnect

---

### Phase 6 — Hardening + Publication 🔲

- [x] `docs/PROTOCOL.md` — full cryptographic protocol specification
- [x] `docs/THREAT_MODEL.md` — trust model, 6 threat actors, comparison table
- [x] `CONTRIBUTING.md` — dev setup, crypto change requirements, responsible disclosure
- [ ] Independent cryptographic audit
- [ ] Post-quantum migration path (ML-KEM / CRYSTALS-Kyber for key encapsulation)
- [ ] Encrypted at-rest session store (Argon2id key derivation)
- [ ] Header encryption (Signal Double Ratchet §3.8)
- [ ] Message replay protection
- [ ] FIPS 140-3 compliance research
- [ ] Conference submission (DEF CON / BSides)

---

## Getting started

### Python (reference implementation + tests)

```bash
git clone https://github.com/m0rs3c0d3/Shadow
cd Shadow
pip install cryptography pytest websockets
python -m pytest tests/ -v
```

Expected: `19 passed`

### Rust CLI

```bash
cd cli
cargo build --release
./target/release/shadow init
./target/release/shadow key show
```

### Mobile (React Native / Expo)

```bash
cd mobile
npm install
npx expo start
```

---

## Security

Shadow has been reviewed for the following issues (fixed):

| Issue | Severity | Fixed |
|-------|----------|-------|
| ECIES AES-GCM called with `AAD=None` | Critical | ✓ `eph_pub` bound as AAD |
| `_unpack_inner` no bounds checks on length fields | High | ✓ Explicit checks added |
| `InitialMessage.deserialize` no bounds checks | High | ✓ Explicit checks added |
| `schnorr_sign` used `assert` (disabled by `-O`) | High | ✓ Replaced with `ValueError` |
| `_ecies_decrypt` no minimum-length check | High | ✓ Rejects blobs < 60 bytes |

Known weaknesses in the current phase are documented in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). To report a vulnerability privately, see [`CONTRIBUTING.md`](CONTRIBUTING.md#9-security-vulnerability-disclosure).

---

## References

- [Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal X3DH specification](https://signal.org/docs/specifications/x3dh/)
- [BIP340 Schnorr signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [Nostr Protocol](https://github.com/nostr-protocol/nostr)
- [Noise Protocol Framework](https://noiseprotocol.org/)

---

## License

MIT. Open source. Auditable. That is the point.
