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

Properties:
- Forward secrecy — past messages are safe even if current keys are compromised
- Break-in recovery — future messages are re-secured after the next DH ratchet step
- Message key independence — each message uses a unique key
- Out-of-order delivery — skipped message keys are stored and used when late messages arrive
- Header integrity — message headers are bound to ciphertext via AEAD associated data

Primitives: X25519 (DH), HKDF-SHA256 (key derivation), AES-256-GCM (AEAD), HMAC-SHA256 (chain ratchet), ed25519 (identity signing).

---

## Repository structure

```
shadow/
├── README.md
├── core/                        # Protocol library (language-agnostic logic)
│   ├── ratchet.py               # Double Ratchet implementation
│   ├── x3dh.py                  # X3DH handshake (Phase 1)
│   └── identity.py              # Keypair generation, device identity
├── transport/                   # Relay / routing layer (Phase 2)
│   └── nostr.py                 # Nostr relay client (default transport)
├── cli/                         # Command-line interface (Phase 4)
│   └── main.py
├── tests/
│   ├── test_ratchet.py          # 8/8 passing — all core properties verified
│   ├── test_x3dh.py
│   └── test_integration.py
├── docs/
│   ├── PROTOCOL.md              # Full protocol specification
│   └── THREAT_MODEL.md          # What Shadow does and does not protect against
└── CONTRIBUTING.md
```

---

## Roadmap

### Phase 0 — Double Ratchet 
**Status: complete. 8/8 tests passing.**

The full Double Ratchet protocol is implemented and verified. All core security properties are tested.

- [x] X25519 DH key exchange
- [x] HKDF-SHA256 root and chain key derivation
- [x] AES-256-GCM AEAD encryption/decryption
- [x] HMAC-SHA256 symmetric chain ratchet (`0x01` / `0x02` constants, Signal spec)
- [x] DH ratchet step on new sender key
- [x] Skipped message key store (up to 1000 skipped keys)
- [x] Forward secrecy test — snapshot of old state cannot decrypt new messages
- [x] Break-in recovery test — attacker with current keys loses access after DH ratchet
- [x] Out-of-order delivery test
- [x] Associated data binding test
- [x] Header integrity / tamper detection test

Reference: [Signal Double Ratchet spec](https://signal.org/docs/specifications/doubleratchet/)

---

### Phase 1 — X3DH Handshake 🔲
**Status: next.**

Implement the X3DH initial key agreement protocol. This is what transforms the ratchet from a standalone encryption library into a real handshake system where two parties who have never communicated can establish a shared secret without being online simultaneously.

**Key types to implement:**
- Identity key (IK) — long-term ed25519 keypair, generated once per device
- Signed prekey (SPK) — medium-term X25519 keypair, signed by IK, rotated weekly
- One-time prekeys (OPK) — ephemeral X25519 keypairs, consumed once per session

**Alice's send flow:**
1. Fetch Bob's prekey bundle (IK, SPK, OPK) from the prekey server
2. Verify SPK signature with Bob's IK
3. Generate ephemeral keypair EK
4. Compute four DH outputs: DH(IK_A, SPK_B), DH(EK, IK_B), DH(EK, SPK_B), DH(EK, OPK_B)
5. Derive shared secret SK = KDF(DH1 || DH2 || DH3 || DH4)
6. Initialize Double Ratchet with SK and Bob's SPK as the initial ratchet key

**Bob's receive flow:**
1. Receive Alice's initial message with her IK and EK
2. Compute the same four DH outputs
3. Derive the same SK
4. Initialize Double Ratchet and decrypt the initial message

**Tasks:**
- [ ] `identity.py` — device keypair generation, persistence, IK signing of SPK
- [ ] `x3dh.py` — sender and receiver flows
- [ ] Prekey bundle serialization (JSON or protobuf)
- [ ] Prekey server stub (in-memory dict is fine for now)
- [ ] Integration test: Alice initiates with Bob offline, Bob receives and decrypts
- [ ] Test: OPK consumed and not reused
- [ ] Test: Session still works when no OPK is available (graceful degradation)

Reference: [Signal X3DH spec](https://signal.org/docs/specifications/x3dh/)

---

### Phase 2 — Transport Layer 🔲
**Status: future.**

The relay layer. Messages need somewhere to go when both parties are not online simultaneously. Three options in order of priority:

**Option A — Nostr relays (start here)**
Use public Nostr relays as the message transport. Nostr is a decentralized protocol with free public relays. Messages are published as encrypted Nostr events. No server to run, no cost, already federated.

**Option B — libp2p**
Fully peer-to-peer. No relay needed. Higher complexity. Better for the long-term decentralized vision.

**Option C — Self-hosted relay**
A minimal SSE relay on a $5/mo VPS. Required for enterprise and government deployments that cannot use public infrastructure.

**Tasks:**
- [ ] `transport/nostr.py` — Nostr relay WebSocket client, publish/subscribe
- [ ] Message envelope format — encrypt sender identity (sealed sender)
- [ ] Contact discovery without a phone number (public key share / QR / invite link)
- [ ] Delivery receipts

---

### Phase 3 — Sealed Sender 🔲
**Status: future.**

Hide metadata — who is messaging whom — from the relay. The relay should only know the destination key, not the sender.

Sender identity is encrypted inside the message envelope using the recipient's public key. The relay sees an opaque blob addressed to a public key fingerprint. It cannot link sender to recipient.

Optional: Tor/onion routing for IP-level anonymity on top of sealed sender.

**Tasks:**
- [ ] Sealed sender envelope format
- [ ] Sender certificate (short-lived, signed by sender IK)
- [ ] Recipient-side decryption and verification
- [ ] Test: relay receives message with no sender information in plaintext

---

### Phase 4 — CLI + TUI 🔲
**Status: future.**

A usable interface. Single binary. No Electron. No browser required.

**Target stack:** Rust — `ratatui` for TUI, `clap` for CLI, `tokio` for async. The Python prototype from Phase 0 gets ported to Rust here using `x25519-dalek`, `chacha20poly1305`, `hkdf`, and `ed25519-dalek`.

**Core commands:**
```
shadow init                  # Generate device identity keypair
shadow add <pubkey>          # Add a contact by public key
shadow send <contact>        # Open interactive message session
shadow recv                  # Poll for new messages
shadow key rotate            # Rotate signed prekey
shadow key show              # Display your public identity key / QR
```

**TUI features:**
- Conversation list and message pane
- Key status panel — ratchet state, last rotation, prekey count
- Ratchet step visualizer (for research / demo use)

**Tasks:**
- [ ] Port `core/ratchet.py` to Rust
- [ ] Port `core/x3dh.py` to Rust
- [ ] CLI skeleton with `clap`
- [ ] TUI layout with `ratatui`
- [ ] Local encrypted key store (SQLite + SQLCipher or flat file + AES)

---

### Phase 5 — Mobile App 🔲
**Status: future.**

Device-native keypair bound to hardware security (iOS Secure Enclave / Android Keystore). No phone number registration flow. Contact discovery via public key QR code or invite link.

**Target stack:** React Native + Expo, or Tauri mobile when it matures.

**Tasks:**
- [ ] Hardware-backed key generation
- [ ] Secure local message store
- [ ] QR code contact add flow
- [ ] Push notification delivery (without leaking metadata)
- [ ] iOS + Android builds

---

### Phase 6 — Hardening + Publication 🔲
**Status: future.**

- [ ] Protocol whitepaper
- [ ] Independent cryptographic audit
- [ ] Post-quantum migration path (CRYSTALS-Kyber / ML-KEM for key encapsulation)
- [ ] FIPS 140-3 compliance research (for government deployments)
- [ ] CVE disclosure process
- [ ] Conference submission (BSides Las Vegas / DEF CON)

---

## Getting started (Phase 0)

```bash
git clone https://github.com/m0rs3c0d3/shadow
cd shadow
pip install cryptography
python tests/test_ratchet.py
```

Expected output:
```
Double Ratchet Protocol — Test Suite
==========================================
  ✓  Basic round-trip
  ✓  Multiple messages one direction
  ✓  Alternating conversation
  ✓  Forward secrecy
  ✓  Break-in recovery
  ✓  Out-of-order delivery
  ✓  Associated data binding
  ✓  Header integrity

==========================================
  8/8 passed
  All properties verified.
```

---

## References

- [Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal X3DH specification](https://signal.org/docs/specifications/x3dh/)
- [Noise Protocol Framework](https://noiseprotocol.org/)
- [Nostr Protocol](https://github.com/nostr-protocol/nostr)
- [libp2p](https://libp2p.io/)

---

## License

MIT. Open source. Auditable. That is the point.
