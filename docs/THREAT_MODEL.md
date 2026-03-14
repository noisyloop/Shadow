# Shadow Threat Model

**Version:** 0.1 (Research Draft)
**Date:** 2026-03-14
**Status:** Pre-audit. Intended for cryptographers and security researchers.

---

## Table of Contents

1. [What Shadow Protects](#1-what-shadow-protects)
2. [What Shadow Does Not Protect Against](#2-what-shadow-does-not-protect-against)
3. [Threat Actor Analysis](#3-threat-actor-analysis)
4. [Sealed Sender: Capabilities and Limitations](#4-sealed-sender-capabilities-and-limitations)
5. [Key Verification Model](#5-key-verification-model)
6. [Post-Compromise Security Properties](#6-post-compromise-security-properties)
7. [Comparison to Related Systems](#7-comparison-to-related-systems)
8. [Known Weaknesses and Future Mitigations](#8-known-weaknesses-and-future-mitigations)

---

## 1. What Shadow Protects

### 1.1 Message Confidentiality (End-to-End Encryption)

**Protected.** The content of every message is encrypted end-to-end using AES-256-GCM with keys derived from the Double Ratchet. No relay, prekey server, or network observer can read message content.

The cryptographic guarantee is: given the ciphertext and the full state of the relay layer, an adversary without either party's current ratchet state cannot decrypt the message. This holds under the assumption that AES-256 is computationally indistinguishable from a random permutation and that the GCM authentication tag (128 bits) is unforgeable under the given key.

### 1.2 Message Integrity and Authentication

**Protected.** Every message is authenticated via AES-256-GCM's 128-bit authentication tag. Any modification to the ciphertext, nonce, or associated data (including the ratchet header) is detected and rejected before any plaintext is produced.

The ratchet header (sender's ratchet public key, previous chain count, message number) is included in the AEAD associated data. A forged or replayed header will cause AEAD verification to fail.

### 1.3 Forward Secrecy

**Protected.** Compromise of a party's current key material does not reveal the content of messages sent before the compromise.

Each message is encrypted with a unique message key derived via HMAC-SHA256 from the current chain key. Message keys are derived, used once, and discarded. The chain key is advanced forward and the old value overwritten. The root key is advanced via HKDF-SHA256 each time a DH ratchet step occurs, using a DH output derived from a freshly generated ephemeral keypair whose private key is immediately deleted.

**Caveat:** Skipped message keys (retained for out-of-order delivery) are stored in `MKSKIPPED` until consumed or until the session is deleted. If state is captured before those keys are consumed, the corresponding messages can be decrypted. This represents a bounded exception to forward secrecy for deferred messages.

### 1.4 Break-in Recovery (Post-Compromise Security)

**Protected.** After a key compromise event, future messages are re-secured once the next DH ratchet step occurs.

The DH ratchet introduces new entropy on every received message that carries a new ratchet public key. Since the new DH private key is generated on-device and never transmitted, an adversary who obtained the prior state cannot compute the new root key or chain keys derived from it.

### 1.5 No Phone Number or Centralized Identity

**Protected.** There is no registration step that ties identity to a phone number, email address, or any government-accessible identifier. Identity is a device-generated 32-byte X25519 public key. The prekey server performs no identity verification.

This protects users from:
- Carrier-level surveillance that identifies users by phone number.
- Legal process targeting phone numbers or email accounts.
- Involuntary disclosure of real-world identity through messenger registration records.

### 1.6 Sender Identity from the Relay

**Protected (with Sealed Sender).** The relay cannot determine the sender of a message. The outer envelope contains only a partial routing hint (first 8 bytes of the recipient's public key). Sender identity is encrypted inside the ECIES-sealed blob and is decryptable only by the recipient.

The relay observes: the recipient key hint (8 bytes), the approximate size of the sealed blob, and the time the message was published. It does not observe: the sender's Shadow identity, or any sender-identifying information.

---

## 2. What Shadow Does Not Protect Against

### 2.1 Compromised Device

If an adversary has code execution on the sender's or recipient's device, all cryptographic protections fail. The adversary can read plaintext before encryption or after decryption, extract private keys from memory or storage, intercept messages at the application layer, and modify the ratchet state.

Shadow assumes the endpoint is trusted. This is a fundamental property of all end-to-end encryption systems. Hardware security modules (iOS Secure Enclave, Android Keystore) can mitigate key extraction but not plaintext access at the application layer.

### 2.2 Timing Analysis and Traffic Analysis

Shadow does not protect against traffic analysis by an adversary who can observe the timing and size of network messages. A relay operator or network observer can determine:

- When a message was sent (from the Nostr event `created_at` timestamp).
- The approximate message size (from the sealed envelope length).
- The recipient routing hint (8 bytes of recipient key).
- The frequency and pattern of communication between a sender's IP and the relay.

Correlating traffic timing across senders and recipients can reveal communication relationships even without reading content. This is a well-known limitation of all messaging systems that do not implement constant-rate or cover-traffic schemes.

### 2.3 ISP-Level IP Address Tracking

An adversary with access to network links can observe:
- The IP addresses of clients connecting to Nostr relays.
- The volume and timing of connections.
- Which relays a user subscribes to and publishes to.

This can be used to correlate senders and recipients even without relay-level observation. Tor integration or a VPN mitigates this. Neither is in scope for the current protocol version.

### 2.4 Compromised or Malicious Contacts

Shadow provides cryptographic authentication of messages (via sender certificates and AEAD) but not authorization. If an adversary has access to a legitimate contact's device or keys, they can send messages that verify correctly under that contact's identity. Authenticated encryption proves only that the message came from the holder of the private key, not that the holder is the expected person.

### 2.5 Government Subpoena of Relay Operator

The Nostr relay operator can be compelled to retain and produce:
- Event metadata: timestamps, recipient key hints, event sizes.
- Stored ciphertexts (not decryptable without recipient keys).
- IP address logs linking Nostr pubkeys to network identities.
- Blocking or throttling of specific Nostr pubkeys.

Message contents remain protected (the relay cannot decrypt them). Shadow minimizes what relay operators can produce in response to legal process. The relay holds ciphertexts and metadata. It does not hold private keys or plaintext. Phone numbers are not part of the Shadow identity model and therefore cannot be produced.

### 2.6 Long-Term Identity Key Compromise

If `ik_dh_priv` or `ik_sign_priv` are compromised:
- The attacker can perform X3DH as Alice, impersonating Alice in new sessions to any contact.
- The attacker can issue valid sender certificates for the duration of the TTL.
- Previously established sessions are not retroactively compromised (forward secrecy protects them).
- New sessions established by the attacker with the compromised key will be transparent to the attacker.

There is no revocation mechanism in the current protocol. A user who suspects key compromise must generate a new identity, inform all contacts through a trusted channel, and destroy the old key.

### 2.7 Prekey Server Compromise

A compromised prekey server can:
- Withhold PreKeyBundles (denial of service — new sessions cannot be established).
- Replay old PreKeyBundles with old SPKs. If the old SPK private key has been deleted per the rotation policy, session establishment fails. If the old key has not yet been deleted (within the grace period), the session is established with a non-current SPK, weakening break-in recovery.
- Substitute a malicious OPK. The attacker does not know the private key of the substituted OPK, so DH4 produces the wrong value, SK is wrong, and the initial message fails to decrypt. This reveals the substitution to Bob.
- Substitute the entire bundle with a different identity. This is the key-substitution attack against first contact, described in Section 5.

### 2.8 Metadata Leakage via Nostr Event Structure

Each Nostr event includes the sender's Nostr pubkey and the recipient's Nostr pubkey in the tags field. A global observer who can correlate Nostr pubkeys across relays can construct a social graph based on communication patterns, without reading any message content.

Shadow's sealed sender protects only against per-event sender identity linkage to Shadow identity keys from the relay layer. It does not prevent persistent Nostr pubkey tracking. Users should use distinct Nostr keypairs per contact or per session.

---

## 3. Threat Actor Analysis

### 3.1 Passive Network Observer (ISP, VPN Exit, Government Tap)

**Capability:** Observes all network traffic between clients and relays. Cannot modify traffic.

**What they learn:**
- Timing and frequency of messages.
- Approximate message sizes (from TLS record sizes).
- IP addresses of users connecting to relays.
- Which relays are used.

**What they cannot learn:**
- Message content (AES-256-GCM encryption).
- Sender Shadow identity (sealed sender).
- Any key material.

**Residual risk:** Traffic analysis correlation. Mitigated by Tor or a VPN (not in current scope) and multi-relay publishing.

**Risk level without Tor:** Moderate. An ISP can determine that a specific IP address communicates with Shadow-associated Nostr relays. They cannot determine the content or the other party's identity.

### 3.2 Active Nostr Relay Operator

**Capability:** Full visibility into relayed events. Can selectively store, forward, delay, or drop events. Can be compelled by legal process.

**What they learn:**
- Sender Nostr pubkey, recipient Nostr pubkey (from event structure).
- Event timestamps.
- Recipient key hint (8 bytes).
- Ciphertext size.

**What they cannot learn:**
- Message content (ECIES + Double Ratchet).
- Sender's Shadow identity (sealed inside ECIES).
- Any information about the message chain or session history.

**Active attack capability:** Message suppression (denial of service). The relay cannot forge messages (AEAD prevents this). The relay cannot perform key substitution (IK is signed by the device).

**Legal process exposure:** Can produce event logs and metadata. Cannot produce plaintext.

### 3.3 Compromised Device

**Capability:** Full code execution on the user's device. Access to all memory and storage.

**What they learn:** Everything. Plaintext, private keys, ratchet state, `MKSKIPPED`, session history, contact list.

**Impact:** Total compromise of all current and potentially future messages. This is outside the scope of Shadow's cryptographic security model. Physical device security, operating system isolation, and application sandboxing are the relevant countermeasures.

**Post-compromise recovery:** After device re-installation and new identity generation, future sessions on the new identity are secure. Contacts must be notified out-of-band.

### 3.4 Government Subpoena or Legal Compulsion

**Capability:** Legal orders served to relay operators, prekey server operators, or in extremis the user themselves.

**Against relay operator:** Event metadata (Nostr pubkeys, timestamps, sizes), stored ciphertexts (not decryptable), IP logs if maintained.

**Against prekey server:** PreKeyBundles (public information; no secret keys), Nostr pubkey-to-IK mappings if logged.

**Against the user:** Can compel device seizure or key production under applicable law. Forward secrecy limits exposure: even a seized device with current keys cannot decrypt messages encrypted before the current chain key was derived. Messages where the chain key has already advanced are inaccessible.

Shadow's design minimizes what third-party servers hold. No server holds private keys or plaintext. There are no phone numbers to subpoena.

### 3.5 Long-Term Key Compromise (Harvest-Now-Decrypt-Later)

**Capability:** An adversary captures ciphertexts and public key material today and decrypts after cryptanalytic advances (including post-quantum attacks).

**Impact against X3DH sessions with OPK:** Requires `EK_A`, `IK_A`, `SPK_B`, and `OPK_B` private keys. `OPK_B.priv` is deleted after X3DH receive. A CRQC (cryptographically relevant quantum computer) could potentially solve X25519 discrete log, making all current long-term keys vulnerable to retroactive decryption.

**Impact against X3DH sessions without OPK:** Requires `IK_A.priv` and `SPK_B.priv`. Since `SPK_B.priv` is rotated weekly and deleted, historical SPK keys may be irrecoverable.

**Impact against Double Ratchet:** Each DH ratchet step uses an ephemeral keypair deleted immediately after use. A CRQC must break these deleted keys retroactively. This is equivalent to solving discrete log on keys that no longer exist as bitstrings, which is not tractable even for a quantum adversary.

**Planned mitigation:** Phase 6 includes migration to ML-KEM (CRYSTALS-Kyber, FIPS 203) for the X3DH key encapsulation layer.

### 3.6 Man-in-the-Middle on First Contact

**Capability:** An adversary (including a compromised prekey server) intercepts the initial X3DH handshake and substitutes their own PreKeyBundle.

**Shadow's protection:**
- The SPK signature is verified by Alice before initiating X3DH. The server cannot fabricate a valid SPK signature without Bob's `ik_sign_priv`.
- The server can substitute the entire bundle including a fake IK and a self-signed SPK. Alice would establish a session with the attacker, believing she is communicating with Bob.

**Detection:** Only possible through out-of-band key verification. Shadow uses TOFU by default (see Section 5).

**Scope:** Applies only to the first message exchange. After both parties have stored each other's IK, any change triggers a key-change warning.

---

## 4. Sealed Sender: Capabilities and Limitations

### 4.1 What Sealed Sender Achieves

Sealed sender prevents the relay from linking a specific sender identity to a specific message. The relay sees only:
- The recipient key hint (8 bytes, not the full key).
- An opaque ECIES-encrypted blob.

The sender's Shadow identity (`ik_dh_pub`) is encrypted inside the blob and is decryptable only by the intended recipient.

### 4.2 Relay Trust Model

The relay is treated as honest-but-curious: it correctly routes messages but may log and analyze everything it observes. Shadow's sender-anonymity properties hold against this model.

If the relay is fully adversarial (actively injecting or modifying messages):
- Injected messages fail AEAD verification (the attacker cannot forge the GCM tag without the message key).
- Modified sealed blobs fail ECIES decryption (GCM tag covers the ECIES inner plaintext).
- Replayed messages succeed (see Section 8.2 for the replay weakness).

### 4.3 Sender Certificate Limitations

**Short-lived but not revocable in real time.** Sender certificates are valid for 24 hours. A certificate issued within a compromise window may be used by an attacker to send authenticated messages until it expires.

**Self-signed.** The certificate is self-signed by the sender's `ik_sign_priv`. There is no certificate authority. Validity means only "the holder of this IK signed this certificate." Whether to trust the IK is determined by the key verification layer, not the certificate itself.

**Not bound to a specific recipient.** The certificate attests to sender identity but does not name the intended recipient. Recipient binding comes from the ECIES encryption: only the intended recipient can decrypt the inner payload containing the certificate.

### 4.4 Key Hint Privacy Analysis

The 8-byte (64-bit) recipient key hint provides approximately 64 bits of routing entropy. Collision probability for a user base of N is approximately `N^2 / 2^65`. For N = 10^6 users, this is approximately `10^-7`.

A passive observer who possesses the universe of public keys (e.g., by scanning the prekey server) can attempt to match the 8-byte hint to a specific user via preimage search. This is a 64-bit preimage search: expensive but potentially feasible for a well-resourced adversary with a complete public key database.

**Implication:** Sealed sender provides strong sender anonymity toward the relay. Recipient anonymity is weaker (64-bit prefix). Full recipient anonymity would require either a longer hint (at the cost of a larger identifier) or private information retrieval (PIR) to remove the hint entirely.

### 4.5 Nostr Pubkey Linkability

The Nostr event's `pubkey` field identifies the sender at the relay-routing level. If a Nostr pubkey is linked to a real-world identity (e.g., a pubkey posted publicly on social media), the association between the real-world identity and the communication is visible to the relay and any observer of the relay.

Shadow's sealed sender hides the Shadow identity keys from the relay; it does not hide the Nostr pubkey. Users who require strong sender anonymity at the transport layer should use ephemeral Nostr keypairs (one per conversation or one per message).

---

## 5. Key Verification Model

### 5.1 Trust on First Use (TOFU)

By default, Shadow uses TOFU: the first time a PreKeyBundle is fetched for a contact, the bundle's identity key is accepted and stored as the canonical key for that contact. Subsequent communications are expected to use the same identity key.

**TOFU threat:** A malicious prekey server can perform a key substitution attack on first contact, returning an attacker-controlled bundle instead of the legitimate user's bundle. Alice will then establish a session with the attacker. This attack is undetectable without out-of-band verification.

**TOFU guarantee:** After first contact is stored, any change to the contact's `ik_dh_pub` triggers a key-change alert. Ongoing sessions are not vulnerable to server-side key substitution as long as the initial stored key was authentic.

### 5.2 Out-of-Band Verification

Users can verify each other's identity keys by comparing key fingerprints through an independent channel (in person, phone call, separate authenticated channel). The recommended fingerprint format is the hex-encoded `ik_dh_pub`, chunked into 8-character groups for readability:

```
AABBCCDD EEFF0011 22334455 66778899 AABBCCDD EEFF0011 22334455 66778899
```

(64 hex characters representing 32 bytes, displayed as 8 groups of 8)

Once fingerprints are verified, the client stores a "verified" flag for the contact. Any subsequent bundle presenting a different `ik_dh_pub` for the same contact triggers a mandatory alert requiring explicit user re-verification.

The CLI command `shadow key show` displays the local identity key in this format, including a QR code for mobile scanning (Phase 4+).

### 5.3 Key Change Detection

If a contact's `ik_dh_pub` changes, Shadow must:
1. Alert the user with a prominent warning.
2. Require explicit user confirmation before establishing a new session with the changed key.
3. Log the key change event with timestamps for audit purposes.

The current implementation does not fully implement this. It is tracked as a required feature before production deployment.

### 5.4 Comparison of Verification Approaches

| Approach | Resistance to MITM on first contact | Usability |
|---|---|---|
| No verification (blind TOFU) | None | Highest |
| TOFU with key pinning | Partial (first-fetch attack possible) | High |
| QR code scan (in-person) | Strong | Medium |
| Voice comparison of safety numbers | Strong | Medium |
| Hardware-attested keys (Secure Enclave) | Very strong | High (Phase 5) |

---

## 6. Post-Compromise Security Properties

### 6.1 Compromise of Current Sending Chain Key (CKs)

**Impact:** The attacker can derive all future message keys in the current sending chain (until the next DH ratchet step). They can decrypt messages encrypted with those keys.

**Recovery:** Automatic on the next DH ratchet step, which occurs when the local party receives a message from the other party carrying a new ratchet public key. No manual intervention is required.

**Maximum exposure window:** All messages sent in the current chain before the next received message from the other party.

### 6.2 Compromise of Root Key (RK)

**Impact:** The attacker can derive all future chain keys and message keys from the point of compromise. Equivalent to full ratchet state compromise.

**Recovery:** Same as CKs compromise — automatic on next DH ratchet step, provided the new DH keypair is generated on an uncompromised device. If the device itself is compromised at the time of the step, the new private key is also captured and the attacker maintains access.

### 6.3 Compromise of Identity Key (IK)

**Impact:**
- Attacker can impersonate the user in new X3DH sessions.
- Attacker can issue valid sender certificates for up to 24 hours.
- Previously established sessions are not retroactively compromised (forward secrecy holds).
- The attacker can engage in new sessions as the victim; recipients will believe they are communicating with the legitimate user unless they perform out-of-band key verification.

**Recovery:** No automatic recovery. Requires:
1. Generation of a new `DeviceIdentity`.
2. Out-of-band notification to all contacts.
3. Secure deletion of the compromised key material.

### 6.4 Compromise of Signed Pre-Key (SPK)

**Impact:** If the SPK that was used to establish a session is compromised after session establishment, and the session was initiated without an OPK, then DH1 (`X25519(IK_A.dh, SPK_B)`) and DH3 (`X25519(EK_A, SPK_B)`) are known. If `IK_A.dh.priv` is also known, SK is computable and the initial message is decryptable.

**Recovery:** The SPK is rotated weekly. After rotation and deletion of the old SPK private key, compromise of the old SPK cannot be used to attack new sessions. Sessions established before the rotation may remain vulnerable until both DH1 and DH3 keys (plus `IK_A.dh.priv`) are simultaneously compromised.

### 6.5 Summary of Recovery Properties

| Compromised value | Decrypts past messages | Decrypts future messages | Recovery mechanism |
|---|---|---|---|
| Single message key (mk) | That message only | No | Automatic (key discarded after use) |
| Chain key (CKs or CKr) | Current chain forward | Until next DH step | Automatic (next DH ratchet) |
| Root key (RK) | All chains forward | Until next DH step | Automatic (next DH ratchet) |
| Full ratchet state | No (one-way ratchet) | Until next DH step | Automatic (next DH ratchet) |
| Identity key (IK) | No (no session keys in IK) | New sessions only | Manual (key rotation + contact notification) |
| Signed pre-key (SPK) | Initial messages (with IK_A) | No (after rotation) | Automatic (weekly SPK rotation) |
| One-time pre-key (OPK) | Initial message (with IK_A, SPK_B) | No (deleted after use) | Automatic (single use) |

---

## 7. Comparison to Related Systems

| Property | Shadow | Signal | Matrix (Element) | SimpleX Chat |
|---|---|---|---|---|
| E2E encryption | Yes (Double Ratchet) | Yes (Double Ratchet) | Yes (Megolm, per-room) | Yes (Double Ratchet) |
| Forward secrecy | Per message | Per message | Per session (Megolm) | Per message |
| Break-in recovery | Yes (DH ratchet) | Yes | Limited (session rotation) | Yes |
| No phone number | Yes | No (required) | No (homeserver account) | Yes |
| Sealed sender | Yes (ECIES) | Yes | No | Partial (queue routing) |
| Decentralized relay | Yes (Nostr) | No (Signal servers) | Yes (homeservers) | Yes (SMP relays) |
| Metadata minimization | Partial (key hint) | Partial (sealed sender) | Limited (homeserver sees metadata) | Strong (no persistent IDs) |
| Post-quantum roadmap | Planned (Phase 6) | Deployed (PQXDH) | In progress | Not documented |
| Identity model | Device keypair | Phone number | Homeserver account | Anonymous queue IDs |
| Key verification | TOFU + OOB (manual) | Safety numbers (UI) | QR code / emoji | Comparison codes |
| Open specification | Yes | Yes | Yes (MSC) | Partial |
| Independent audit | Planned | Yes (multiple) | Partial | Limited |
| Hardware key backing | Phase 5 (planned) | Yes (iOS/Android) | No | No |
| Group messaging | Not yet | Sender Keys | Megolm | Not yet |
| Open source | Yes (MIT) | Yes (GPL) | Yes (Apache) | Yes (AGPL) |

**Notes:**

- **Megolm (Matrix):** Uses a single ratchet shared across all room members. Per-message forward secrecy requires explicit session rotation rather than occurring automatically on each DH step. Group sessions provide weaker per-message forward secrecy than 1:1 Double Ratchet sessions. Shadow does not currently support group messaging.

- **SimpleX:** Uses a queue-based delivery model that provides strong infrastructure-level sender/recipient unlinkability, stronger than Shadow's current key-hint approach. Contact establishment is more complex but offers better metadata protection. SimpleX does not use long-term identity keys; instead it uses per-contact queue identifiers.

- **Signal PQXDH:** Signal has deployed a post-quantum variant of X3DH using ML-KEM-1024 (formerly Kyber-1024) in addition to X25519. This provides security against harvest-now-decrypt-later attacks even against a future CRQC. Shadow's Phase 6 plans a similar migration.

- **Nostr transport:** Shadow's use of Nostr as a transport layer provides censorship resistance and federation that Signal's centralized infrastructure does not. However, Nostr pubkey linkability is a metadata leak that centralized systems (Signal) partially address through their own sealed sender implementation.

---

## 8. Known Weaknesses and Future Mitigations

### 8.1 No Header Encryption

**Current state:** The Double Ratchet header (sender DH key, chain number, message number) is authenticated but not encrypted. It is transmitted as plaintext within the sealed sender inner payload.

**Impact:** Within the ECIES envelope, the header is protected. After ECIES decryption, the header is visible in plaintext to the recipient. An adversary who breaks the outer ECIES encryption (computationally infeasible with current hardware against AES-256-GCM) would see the header.

**Mitigation planned:** Header encryption as described in Signal Double Ratchet Section 3.8, using header keys derived from the ratchet state. This is a future protocol version feature.

### 8.2 No Message Replay Protection

**Current state:** There is no nonce, timestamp, or sequence number in the protocol layer that prevents a relay from replaying a previously delivered message.

**Impact:** A relay can replay an old message. The recipient will successfully decrypt it (using a key from `MKSKIPPED` if the message number is old, or as an apparent duplicate if recent). The recipient has no cryptographic way to detect the replay.

**Mitigation at application layer:** Applications can maintain a set of seen message IDs derived from a hash of the ciphertext or the ratchet chain-and-message-number tuple `(dh_pub, n)`. Duplicate `(dh_pub, n)` tuples from the same sender should be discarded.

**Mitigation planned:** Explicit per-message ID field in the wire format with application-level deduplication stored in the session database.

### 8.3 Skipped Key Expiry

**Current state:** Skipped message keys in `MKSKIPPED` have no time-to-live. They persist until consumed or until the session state is explicitly deleted.

**Impact:** If session state is captured (e.g., from a backup) after message keys have been pre-derived but before the corresponding messages arrived, those messages can be decrypted. This represents a bounded but indefinite weakening of forward secrecy for in-flight messages.

**Mitigation planned:** Configurable TTL for skipped keys (e.g., 7 days). Keys older than the TTL are deleted without being consumed. Late messages arriving after TTL expiry will fail to decrypt. This is a configurable availability-security trade-off.

### 8.4 At-Rest Session State Not Encrypted

**Current state:** Session state (ratchet state, keys, `MKSKIPPED`) is stored as plaintext JSON on disk in the CLI implementation.

**Impact:** Local disk compromise reveals all current ratchet keys and pre-derived skipped keys. Past messages whose keys have been advanced past the current chain key are still protected by forward secrecy.

**Mitigation planned:** Encrypt session store with a 256-bit key derived from a user passphrase via Argon2id (m=65536, t=3, p=4). This provides protection against offline disk attacks without requiring an HSM.

### 8.5 OPK Pool Exhaustion

**Current state:** When the OPK pool is exhausted, X3DH falls back to a 3-DH construction (DH1, DH2, DH3 only). The current implementation does not alert the user or client to OPK exhaustion.

**Impact:** Sessions initiated without an OPK provide weaker initial forward secrecy. Compromise of `spk.priv` (within the rotation window) and `alice.ik_dh_priv` is sufficient to compute SK for those sessions. Sessions established with an OPK require additionally compromising the (deleted) `opk.priv`.

**Mitigation:** Automatic OPK replenishment when pool falls below threshold (implemented in `PrekeyServer` stub; must be integrated into the production client). Client-side alert when replenishment fails.

### 8.6 Pure Python Schnorr Implementation

**Current state:** The Nostr transport layer uses a pure Python implementation of BIP340 Schnorr signatures on secp256k1. This implementation is not constant-time.

**Impact:** Timing side-channel attacks against Schnorr signing could potentially reveal the Nostr private key. However, the Nostr keypair is separate from the Shadow identity key. Compromise of the Nostr keypair allows an attacker to sign relay events as the victim but does not enable decryption of any messages.

**Mitigation planned:** Replace with a constant-time library implementation (the Rust CLI port uses the constant-time `x25519-dalek` and `ed25519-dalek` crates and does not use this Python path for production signing).

### 8.7 Prekey Server Trust Model

**Current state:** No prekey server authentication. The prekey server is accessed by URL, and the client trusts the bundle that is returned.

**Impact:** DNS hijacking or a compromised prekey server can perform key substitution attacks on first contact. TOFU partially mitigates this (only the first contact is vulnerable; subsequent contacts use the stored key).

**Mitigation planned:** Signed bundle aggregation with a transparency log (analogous to Certificate Transparency for TLS), allowing detection of equivocation by the prekey server. Short-term: key pinning after first verified contact, surfacing any deviation to the user.

### 8.8 No Group Messaging

**Current state:** Shadow v0.1 supports only 1:1 messaging.

**Impact:** Group communications must be implemented at the application layer as N pairwise sessions. This does not scale and does not provide the sender-key efficiency of Megolm or Signal's Sender Keys protocol (RFC in progress).

**Mitigation planned:** Sender Key protocol for group messaging. Each group member generates a Sender Key and shares it with the group, encrypted for each member via their individual Double Ratchet session. This provides per-message forward secrecy for 1:many communication with O(N) delivery overhead.

### 8.9 No Independent Cryptographic Audit

**Current state:** Shadow has not received an independent cryptographic audit.

**Impact:** Unknown implementation bugs may exist in the ratchet state machine, wire format parsing, or key derivation. The protocol design follows published specifications (Signal Double Ratchet, Signal X3DH) that have been formally analyzed, but implementation bugs are distinct from design bugs.

**Mitigation:** An independent cryptographic audit is planned as Phase 6 work prior to production deployment. Security researchers are encouraged to review and report findings via the private disclosure process documented in `CONTRIBUTING.md`. The test suite (18 tests across ratchet, X3DH, and integration layers) covers all key protocol properties.

### 8.10 Sender Certificate Not Bound to Message

**Current state:** A sender certificate attests to sender identity with a 24-hour TTL but does not bind to a specific message, session, or recipient.

**Impact:** An attacker who obtains a decrypted inner payload (e.g., after compromise of the recipient's device) could re-use the embedded certificate in a different context to attest to the sender's identity falsely. However, re-using the certificate outside the sealed envelope context does not give the attacker access to message content or the ability to forge new messages under the sender's key.

**Mitigation planned:** Bind the sender certificate to the session by including a session nonce or the Double Ratchet header hash in the signed body. This prevents certificate reuse outside of the specific sealed envelope context.
