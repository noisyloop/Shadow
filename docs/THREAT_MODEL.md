# Shadow Threat Model

Version 0.1

---

## 1. Goals

Shadow is designed to protect:

1. **Message confidentiality** — only the sender and recipient can read messages
2. **Forward secrecy** — past messages remain secure if current keys are compromised
3. **Break-in recovery** — after a DH ratchet step, an attacker who obtained current keys loses access to future messages
4. **Sender anonymity from relay** — the relay cannot determine who sent a message (Sealed Sender)
5. **Identity independence from phone numbers** — no government-accessible identifier required

---

## 2. Trust Assumptions

| Component            | Trust level  | Notes                                         |
|----------------------|-------------|-----------------------------------------------|
| Sender device        | Trusted     | You own it                                    |
| Recipient device     | Trusted     | Assumed not compromised                       |
| Nostr relay          | Untrusted   | Stores and routes ciphertexts only            |
| Prekey server        | Semi-trusted | Serves public key bundles; cannot read content |
| Network              | Untrusted   | Passive eavesdropping assumed                 |
| Contact's identity   | TOFU        | Trust-on-first-use; verify out-of-band        |

---

## 3. Threat Actors

### 3.1 Passive Network Observer (e.g. ISP, VPN exit)

**Capability**: records all network traffic between client and relay.

**What they can see**:
- That you are connecting to a Nostr relay
- Packet sizes and timing
- Frequency of communication (metadata)

**What they cannot see**:
- Message content (AES-256-GCM)
- Who you are communicating with (sealed sender)
- Your Shadow identity key

**Mitigation**: use Tor or a trusted VPN for IP-level anonymity.

---

### 3.2 Active Relay Operator

**Capability**: full access to all data stored on and passing through the relay.

**What they can see**:
- Nostr event pubkeys (secp256k1 routing keys, not Shadow identity keys)
- Recipient key hint (first 8 bytes of recipient IK pub)
- Ciphertext sizes and timestamps
- Number of messages between parties (if sender and recipient Nostr keys are linked)

**What they cannot see**:
- Shadow identity keys (IK_dh, IK_sign)
- Message plaintext
- Sender identity (sealed sender encrypts sender cert inside ECIES envelope)
- Ratchet state

**Mitigation**: use separate Nostr keypairs per conversation; use multiple relays.

---

### 3.3 Compromised Device (post-compromise)

**Capability**: attacker has full access to the device's memory and storage at time T.

**What they can read**:
- All message history stored on device
- The current ratchet state, including current chain keys
- The device identity keypair (IK_dh, IK_sign)
- All contacts and sessions

**What they cannot read** (post-compromise recovery):
- Messages encrypted after the next DH ratchet step, if the device is clean
- Future messages once the ratchet has advanced past the compromise point

**What is permanently lost**:
- The identity keypair — if the attacker exfiltrates IK, they can impersonate you until contacts rotate keys

**Mitigation**: hardware-backed key storage (Phase 5, iOS Secure Enclave / Android Keystore) prevents key exfiltration even on a rooted device.

---

### 3.4 Government Subpoena / Legal Process

**Capability**: legal compulsion against relay operators or infrastructure providers.

**What they can obtain from relay**:
- Ciphertexts (not useful without keys)
- Nostr event metadata (pubkeys, timestamps, sizes)
- IP addresses used to connect to relay (mitigated by Tor)

**What they cannot obtain** (short of device seizure):
- Message plaintext
- Shadow identity keys (stored on device only)

**Note**: phone numbers are not used in Shadow. There is no phone number to subpoena.

---

### 3.5 Attacker with Current Chain Keys

**Capability**: attacker obtains the current `CKs` or `CKr` chain key at time T (e.g. via memory dump).

**What they can decrypt**:
- All messages in the current chain (from position `Nr` onwards)

**What they cannot decrypt** (break-in recovery):
- Messages after the next DH ratchet step — the new root key requires `DH(DHs_new, DHr)`, which requires the sender's new DH private key

**Recovery timeline**: after one full round trip (Alice sends, Bob replies), both parties have completed a DH ratchet step and the attacker's chain key is useless.

---

### 3.6 Man-in-the-Middle (first contact)

**Capability**: attacker intercepts the initial X3DH handshake, substitutes their own prekey bundle.

**Shadow's protection**:
- The SPK signature is verified by Alice before initiating X3DH
- But: Alice has no way to verify that the IK in the bundle is Bob's IK without out-of-band verification

**Required mitigation**: users must verify each other's identity keys out-of-band (QR code scan, voice call, in-person). Shadow's `shadow key show` command displays the QR code for this purpose.

Shadow uses **Trust on First Use (TOFU)** by default. This is weaker than key verification but stronger than phone-number-based identity.

---

## 4. What Shadow Does NOT Protect Against

| Threat                                | Status     | Notes                                        |
|---------------------------------------|-----------|----------------------------------------------|
| Device compromise / malware           | ✗ No       | Full device access = full message access     |
| Recipient compromise                  | ✗ No       | Cannot control the other side                |
| Traffic analysis by ISP               | Partial    | Sizes and timing are visible; Tor mitigates  |
| Rubber-hose cryptanalysis             | ✗ No       | Coercion is not a cryptographic problem      |
| QR code MITM (first contact)          | Partial    | Out-of-band verification required            |
| Compromised Nostr relay (metadata)    | Partial    | Sealed sender hides sender; timing remains   |
| Malicious contact                     | ✗ No       | Cannot prevent a contact from leaking msgs   |
| Post-quantum adversary                | ✗ No       | X25519 and ed25519 are not PQ-secure (Phase 6)|

---

## 5. Sealed Sender Limitations

Sealed sender hides the sender's Shadow identity from the relay. However:

- The relay still sees the sender's **Nostr pubkey** (secp256k1 routing key). If this is linked to real-world identity, the association is visible.
- The recipient key hint (8-byte prefix) could theoretically collide for different recipients. In practice, with 2^64 possible 8-byte values, collisions are negligible at any realistic scale.
- The relay knows the **size** and **timing** of messages. Traffic analysis can infer conversation patterns.

---

## 6. Comparison

| Property                    | Shadow | Signal | Matrix | SimpleX |
|-----------------------------|--------|--------|--------|---------|
| Phone number required       | No     | Yes    | No     | No      |
| Forward secrecy             | Yes    | Yes    | Yes†   | Yes     |
| Break-in recovery           | Yes    | Yes    | Partial| Yes     |
| Sealed sender               | Yes    | Yes    | No     | Yes     |
| Decentralised relay         | Yes    | No     | Yes    | Yes     |
| Open source crypto          | Yes    | Yes    | Yes    | Yes     |
| Hardware key backing        | Phase 5| Yes    | No     | No      |
| Post-quantum (planned)      | Phase 6| Planned| No    | No      |

† Matrix Megolm does not have per-message DH ratchet; forward secrecy granularity is per-session.

---

## 7. Known Weaknesses (Current Phase)

1. **No key verification UI** — users can only verify keys by comparing hex manually. Phase 4 adds QR scan; Phase 5 adds in-app verification ceremony.
2. **Prekey server trust** — if the prekey server is compromised, it could substitute malicious OPKs (but not fake SPK signatures). Mitigated by SPK signature verification.
3. **Unencrypted local store** — Phase 4 stores keys as plaintext JSON. Phase 4 planned mitigation: AES-256-GCM store key derived from OS credential store.
4. **No OPK replenishment signal** — the server does not actively notify clients when OPK pool is low.
5. **Nostr key linkability** — reusing the same Nostr pubkey across conversations links those conversations at the relay level.

---

## 8. Reporting Security Issues

Security vulnerabilities should be reported privately. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the disclosure process. Do not open public GitHub issues for security bugs.
