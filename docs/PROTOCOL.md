# Shadow Protocol Specification

**Version:** 0.1 (Research Draft)
**Date:** 2026-03-14
**Status:** Pre-audit. Suitable for cryptographic review.

---

## Table of Contents

1. [Overview and Design Goals](#1-overview-and-design-goals)
2. [Cryptographic Primitives](#2-cryptographic-primitives)
3. [Key Types and Identity Model](#3-key-types-and-identity-model)
4. [X3DH: Initial Key Agreement](#4-x3dh-initial-key-agreement)
5. [Double Ratchet: Session Encryption](#5-double-ratchet-session-encryption)
6. [Sealed Sender](#6-sealed-sender)
7. [Message Wire Formats](#7-message-wire-formats)
8. [Key Rotation Policies](#8-key-rotation-policies)
9. [Session Initialization and Teardown](#9-session-initialization-and-teardown)
10. [Out-of-Order Delivery](#10-out-of-order-delivery)
11. [Forward Secrecy and Break-in Recovery](#11-forward-secrecy-and-break-in-recovery)
12. [References](#12-references)

---

## 1. Overview and Design Goals

Shadow is an end-to-end encrypted messaging protocol designed around three non-negotiable properties:

1. **No phone number required.** Identity is a device-generated keypair. There is no registration step, no KYC-linked identifier, and no centrally-issued account handle. A user's cryptographic identity is the 32-byte compressed public key of their identity keypair.

2. **End-to-end encryption with forward secrecy and break-in recovery.** Every message is encrypted with a unique per-message key derived from two ratchets running in parallel. Compromise of current key material does not reveal past messages (forward secrecy) and does not permanently compromise future messages (break-in recovery).

3. **Metadata reduction via sealed sender.** The relay layer learns the destination of a message (as a routing hint) but cannot determine the sender. Sender identity is encrypted inside the message envelope and is verifiable only by the recipient.

**Secondary design goals:**

- Minimal dependencies. Each cryptographic layer uses one well-specified primitive. No custom constructions.
- Auditability. A cryptographer familiar with the Signal specifications should be able to audit the full implementation in a single session.
- Transport-agnostic. The protocol layer is decoupled from the relay. The default transport is Nostr (kind-14 encrypted DMs), but nothing in the protocol requires it.
- Language portability. A reference Python implementation (`core/`) and a production Rust port (`cli/src/crypto/`) exist with identical semantics. Test vectors are shared.

Shadow deliberately does not provide:

- Anonymity at the network layer (no onion routing in this version).
- Group messaging (out of scope for v0.1).
- Deniability beyond what the Double Ratchet naturally provides.
- Post-quantum security (tracked as Phase 6 work; planned migration to ML-KEM).

---

## 2. Cryptographic Primitives

### 2.1 Summary Table

| Purpose | Primitive | Parameters | Justification |
|---|---|---|---|
| Diffie-Hellman | X25519 | 255-bit curve, 32-byte keys | Constant-time, cofactor-safe, fast; standard for Noise/Signal |
| Identity signatures | Ed25519 | RFC 8032, 32-byte keys, 64-byte sigs | Widely reviewed; deterministic signing prevents nonce reuse |
| Key derivation (root/chain) | HKDF-SHA256 | 64-byte output, split to 2x32 | NIST-approved; PRF security under standard assumptions |
| Symmetric encryption | AES-256-GCM | 256-bit key, 96-bit random nonce, 128-bit tag | NIST FIPS 197 + SP 800-38D; hardware acceleration on all target platforms |
| Chain ratchet | HMAC-SHA256 | NIST FIPS 198-1 | PRF with key separation via distinct 1-byte input constants |
| Transport signatures | Schnorr/secp256k1 | BIP340, x-only pubkeys | Nostr compatibility; Nostr identity is separate from Shadow identity |

### 2.2 X25519

X25519 (RFC 7748) is used for all Diffie-Hellman operations. Keys are 32 raw bytes representing the u-coordinate of a point on Curve25519. The field prime is `2^255 - 19`.

**Justification:** X25519's design enforces constant-time scalar multiplication via clamping (bits 0, 1, 2, 255 of the scalar are forced). This prevents timing side-channels in software implementations without requiring platform-specific countermeasures. The cofactor-8 design means small-subgroup attacks are neutralized by the clamping. All-zero output is checked and rejected at the library level in both the Python (`cryptography`) and Rust (`x25519-dalek`) implementations.

**Key representation:** Private keys are stored as 32 raw bytes. Public keys are stored as 32-byte little-endian u-coordinates (the standard X25519 encoding). No point compression or decompression is required.

### 2.3 Ed25519

Ed25519 (RFC 8032) is used exclusively for identity signing operations: signing the Signed Pre-Key public key, and self-signing sender certificates. Keys are 32 bytes (compressed Edwards y-coordinate). Signatures are 64 bytes.

**Justification:** Deterministic signature generation (the nonce is derived from the private key and message via a hash) eliminates the class of vulnerabilities caused by weak RNG at signing time (the ECDSA/Sony PlayStation failure mode). Ed25519 verification is constant-time in both reference implementations used.

**Domain separation:** Ed25519 is used only for authentication (SPK signature, sender certificate). It is never used for key agreement. The identity keypair has two independent sub-keys: `ik_dh` (X25519, for DH) and `ik_sign` (Ed25519, for signing). These are distinct keys generated independently, not derived from each other.

### 2.4 HKDF-SHA256

HKDF (RFC 5869) with SHA-256 is used for all key derivation that takes Diffie-Hellman output as input.

**KDF_RK construction (Double Ratchet root key step):**

```
KDF_RK(rk, dh_out) -> (new_rk, ck)

HKDF-Extract:  PRK = HMAC-SHA256(salt=rk, ikm=dh_out)
HKDF-Expand:   OKM = HKDF-Expand(PRK, info=b"ShadowRootKey", length=64)
new_rk = OKM[0:32]
ck     = OKM[32:64]
```

The root key serves as the HKDF salt, binding the new root key and chain key cryptographically to all prior DH ratchet steps.

**KDF_X3DH construction (initial key agreement):**

```
KDF_X3DH(DH1, DH2, DH3[, DH4]) -> SK

IKM = b"\xff" * 32 || DH1 || DH2 || DH3 [|| DH4]
PRK = HMAC-SHA256(salt=b"\x00" * 32, ikm=IKM)
SK  = HKDF-Expand(PRK, info=b"ShadowX3DH", length=32)
```

The 32-byte `0xFF` prefix (F) is the Signal X3DH spec's domain-separation constant. It prevents any single DH output from being trivially recognizable as the full IKM.

### 2.5 AES-256-GCM

AES-256-GCM (NIST SP 800-38D) is the AEAD used for all message encryption.

**Parameters:**
- Key: 32 bytes (256 bits), derived from the message key ratchet.
- Nonce: 12 bytes (96 bits), generated from `os.urandom(12)` (Python) or `OsRng` (Rust) for each encryption. Nonces are not reused because each message uses a fresh message key; the random nonce provides additional security margin against state duplication bugs.
- Tag: 128 bits (GCM default). Verification failure causes immediate rejection of the ciphertext.
- Associated Data: The outer AD passed by the application, concatenated with a 4-byte big-endian length prefix and the serialized ratchet header. See Section 5.5.

**Justification:** AES-256-GCM provides authenticated encryption. The GCM tag covers both the ciphertext and the associated data, meaning any modification to the header or ciphertext is detected before decryption proceeds. AES-NI instructions are available on all x86-64 and ARMv8 target platforms, eliminating timing channels in the AES core.

### 2.6 HMAC-SHA256

HMAC-SHA256 (NIST FIPS 198-1) is used for the symmetric chain ratchet step only.

**KDF_CK construction:**

```
KDF_CK(ck) -> (new_ck, mk)

new_ck = HMAC-SHA256(key=ck, msg=b"\x01")
mk     = HMAC-SHA256(key=ck, msg=b"\x02")
```

The 1-byte input constants `0x01` and `0x02` provide domain separation between the next chain key and the message key derived from the same chain key. This matches the Signal Double Ratchet specification Section 2.2.

---

## 3. Key Types and Identity Model

### 3.1 Device Identity

A Shadow identity is a pair of independent keypairs generated on device:

```
DeviceIdentity:
  ik_dh_priv   [32 bytes]  X25519 private key  -- DH operations in X3DH
  ik_dh_pub    [32 bytes]  X25519 public key   -- published in prekey bundle
  ik_sign_priv [32 bytes]  Ed25519 seed        -- signs SPK, sender certificates
  ik_sign_pub  [32 bytes]  Ed25519 verifying key -- published in prekey bundle
```

These keys are generated once and stored on-device. They are the user's persistent identity. The 32-byte `ik_dh_pub` is the canonical user identifier for routing purposes.

### 3.2 Signed Pre-Key (SPK)

A medium-term X25519 keypair, signed by the identity signing key. Rotated weekly (see Section 8).

```
SignedPreKey:
  id         uint32       monotonically increasing identifier
  priv_key   [32 bytes]   X25519 private key (never leaves device)
  pub_key    [32 bytes]   X25519 public key (published in bundle)
  signature  [64 bytes]   Ed25519 signature of pub_key by ik_sign_priv
```

The signature covers exactly `pub_key` (32 bytes). Verifiers check `Ed25519_verify(ik_sign_pub, pub_key, signature)` before using the bundle.

### 3.3 One-Time Pre-Keys (OPK)

Ephemeral X25519 keypairs. Each OPK is consumed exactly once. The server removes it from the pool on fetch, and Bob's device deletes the private key after the X3DH receive.

```
OneTimePreKey:
  id       uint32     identifier (scoped to a device)
  priv_key [32 bytes] X25519 private key (never leaves device)
  pub_key  [32 bytes] X25519 public key (published in bundle)
```

OPKs are unsigned. Their authenticity is protected indirectly: if an OPK were substituted by a malicious server, the attacker would still need to possess the corresponding private key to complete the DH operation, which they do not. DH4 would produce the wrong value, SK would be wrong, and initial message decryption would fail, revealing the substitution.

When the OPK pool is exhausted, X3DH falls back to a 3-DH construction (DH1, DH2, DH3 only). This is a security degradation (no OPK forward secrecy) but not a protocol failure. See Section 11.3.

### 3.4 PreKey Bundle

The public bundle published to the prekey server:

```
PreKeyBundle:
  identity_key      [32 bytes]           IK DH public key
  identity_sign_key [32 bytes]           IK signing public key
  spk_id            uint32               current SPK identifier
  spk_public        [32 bytes]           current SPK public key
  spk_signature     [64 bytes]           Ed25519(ik_sign_priv, spk_public)
  opk_id            uint32 or absent     OPK identifier, if one is attached
  opk_public        [32 bytes] or absent OPK public key
```

The server stores the bundle without an attached OPK and dynamically attaches one OPK from the device's pool on each fetch request, then removes that OPK from the pool.

---

## 4. X3DH: Initial Key Agreement

Shadow's X3DH implementation follows the Signal X3DH specification (Marlinspike and Perrin, 2016) with minor adaptations. The protocol establishes a shared secret `SK` between Alice (initiator) and Bob (responder) without requiring Bob to be online.

### 4.1 Roles and Prerequisites

- **Alice** wants to send a message to Bob.
- **Bob** has published a PreKeyBundle to a prekey server.
- **Prekey server** is an untrusted store. It can withhold, delay, or replay bundles, but cannot forge the SPK signature.

### 4.2 Alice's Send Flow

```
Input:
  alice         -- Alice's DeviceIdentity
  bob_bundle    -- Bob's PreKeyBundle (fetched and verified)
  plaintext     -- the initial message body
  AD            -- application-level associated data

Steps:

1. Verify SPK signature:
   Ed25519_verify(bob_bundle.identity_sign_key,
                  bob_bundle.spk_public,
                  bob_bundle.spk_signature)
   Abort if verification fails.

2. Generate ephemeral key:
   EK_A = X25519_generate()

3. Compute DH outputs:
   DH1 = X25519(alice.ik_dh_priv, bob_bundle.spk_public)   // auth: IK_A <-> SPK_B
   DH2 = X25519(EK_A.priv,        bob_bundle.identity_key)  // auth: EK_A <-> IK_B
   DH3 = X25519(EK_A.priv,        bob_bundle.spk_public)    // forward secrecy
   DH4 = X25519(EK_A.priv,        bob_bundle.opk_public)    // one-time forward secrecy
         (DH4 included only if bob_bundle.opk_public is present)

4. Derive shared secret:
   SK = KDF_X3DH(DH1, DH2, DH3[, DH4])

5. Initialize Double Ratchet:
   alice_state = RatchetInitAlice(SK, bob_bundle.spk_public)

6. Encrypt initial message:
   (header, ct) = RatchetEncrypt(alice_state, plaintext, AD)

Output:
  InitialMessage {
    ik_pub:       alice.ik_dh_pub,
    ek_pub:       EK_A.pub,
    spk_id:       bob_bundle.spk_id,
    opk_id:       bob_bundle.opk_id (or absent),
    header_bytes: header.serialize(),
    ciphertext:   ct,
  }
  alice_state  (retained for subsequent messages)
```

**Security properties provided by DH1 through DH4:**

| DH | Sender key | Receiver key | Contribution |
|---|---|---|---|
| DH1 | IK_A (long-term) | SPK_B (medium-term) | Mutual authentication: proves Alice knows IK_A; SPK_B is signed by IK_B |
| DH2 | EK_A (ephemeral) | IK_B (long-term) | Proves Bob's identity participated; contributes freshness |
| DH3 | EK_A (ephemeral) | SPK_B (medium-term) | Ephemeral-to-medium-term forward secrecy |
| DH4 | EK_A (ephemeral) | OPK_B (one-time) | One-time forward secrecy; limits key reuse window |

### 4.3 Bob's Receive Flow

```
Input:
  bob       -- Bob's DeviceIdentity
  spk       -- Bob's SignedPreKey (looked up by msg.spk_id)
  opk       -- Bob's OneTimePreKey (looked up by msg.opk_id, or None)
  msg       -- InitialMessage received from Alice
  AD        -- application-level associated data (must match Alice's)

Steps:

1. Recompute DH outputs (same values, reversed key roles):
   DH1 = X25519(spk.priv,         msg.ik_pub)   // SPK_B <-> IK_A
   DH2 = X25519(bob.ik_dh_priv,   msg.ek_pub)   // IK_B  <-> EK_A
   DH3 = X25519(spk.priv,         msg.ek_pub)   // SPK_B <-> EK_A
   DH4 = X25519(opk.priv,         msg.ek_pub)   // OPK_B <-> EK_A (if opk != None)

2. Derive shared secret:
   SK = KDF_X3DH(DH1, DH2, DH3[, DH4])

3. Initialize Double Ratchet:
   bob_state = RatchetInitBob(SK, spk_pair=(spk.priv, spk.pub))

4. Decrypt initial message:
   header    = Header.deserialize(msg.header_bytes)
   plaintext = RatchetDecrypt(bob_state, header, msg.ciphertext, AD)

5. Delete OPK private key from local store.

Output:
  plaintext
  bob_state  (retained for subsequent messages)
```

### 4.4 KDF Construction Detail

```
F    = b"\xff" * 32       (32-byte constant, domain separator)
SALT = b"\x00" * 32       (32-byte zero salt)
INFO = b"ShadowX3DH"      (10-byte ASCII context label)

IKM  = F || DH1 || DH2 || DH3 [|| DH4]
     = 32 + 32 + 32 + 32 [+ 32] bytes = 128 or 160 bytes total

PRK  = HMAC-SHA256(key=SALT, msg=IKM)            (HKDF-Extract)
SK   = HMAC-SHA256(key=PRK, msg=INFO || 0x01)    (HKDF-Expand, L=32, first block)
```

The `F` prefix ensures the full IKM is unambiguously distinguishable from any single DH output or partial concatenation. The zero salt is used rather than a random salt because HKDF-Extract with a zero salt degrades gracefully to HMAC with a standard key; the domain separation comes from `F` and `INFO`.

### 4.5 Associated Data

The associated data `AD` passed to the initial ratchet encryption must include both parties' long-term identity keys. Recommended construction:

```
AD = alice.ik_dh_pub || bob.identity_key
```

This binds the AEAD to the identity of both parties, preventing key-substitution attacks against the initial message.

---

## 5. Double Ratchet: Session Encryption

Shadow's Double Ratchet follows the Signal Double Ratchet specification (Marlinspike and Perrin, 2016). The ratchet provides per-message key derivation, forward secrecy, and break-in recovery.

### 5.1 State

```
RatchetState:
  DHs        (priv: [32], pub: [32])   own current ratchet DH keypair
  DHr        [32] or None              remote party's current ratchet public key
  RK         [32]                      root key
  CKs        [32] or None              sending chain key
  CKr        [32] or None              receiving chain key
  Ns         uint32                    sending message counter
  Nr         uint32                    receiving message counter
  PN         uint32                    previous chain message count
  MKSKIPPED  Map<(dh_pub, n), [32]>    skipped message keys, bounded by MAX_SKIP=1000
```

All byte arrays are 32 bytes. Counters are unsigned 32-bit integers.

### 5.2 Initialization

**Alice (initiator), called after X3DH with SK and bob_spk_pub:**

```
RatchetInitAlice(SK, bob_spk_pub):
  DHs = X25519_generate()
  (RK, CKs) = KDF_RK(SK, X25519(DHs.priv, bob_spk_pub))
  DHr = bob_spk_pub
  CKr = None
  Ns = Nr = PN = 0
  MKSKIPPED = {}
```

Alice immediately performs a DH ratchet step, deriving the first sending chain key. She is ready to send.

**Bob (responder), called after X3DH with SK and his SPK pair:**

```
RatchetInitBob(SK, spk_pair):
  DHs = spk_pair    (Bob's SPK becomes his initial ratchet key)
  DHr = None
  RK  = SK
  CKs = CKr = None
  Ns = Nr = PN = 0
  MKSKIPPED = {}
```

Bob does not perform any DH step yet. His first receiving chain key is derived when he receives Alice's first message header.

### 5.3 KDF Functions

**KDF_RK** (HKDF-SHA256, produces 64 bytes split into two 32-byte keys):

```
KDF_RK(rk, dh_out):
  OKM = HKDF-SHA256(salt=rk, ikm=dh_out, info=b"ShadowRootKey", length=64)
  return (OKM[0:32], OKM[32:64])     // (new_rk, ck)
```

**KDF_CK** (HMAC-SHA256 with 1-byte constants):

```
KDF_CK(ck):
  new_ck = HMAC-SHA256(key=ck, msg=b"\x01")
  mk     = HMAC-SHA256(key=ck, msg=b"\x02")
  return (new_ck, mk)
```

### 5.4 Encrypt Algorithm

```
RatchetEncrypt(state, plaintext, AD):
  (state.CKs, mk) = KDF_CK(state.CKs)
  header = Header(dh=state.DHs.pub, pn=state.PN, n=state.Ns)
  state.Ns += 1
  aad = concat_AD(AD, header)
  ct  = AES256GCM_Encrypt(key=mk, nonce=random(12), pt=plaintext, aad=aad)
  return (header, nonce || ct)
```

### 5.5 Associated Data Construction

The message key's AEAD associated data binds the ratchet header to the ciphertext, preventing header substitution:

```
concat_AD(AD, header):
  hdr_bytes = header.serialize()   // 40 bytes
  return AD || BE32(len(hdr_bytes)) || hdr_bytes
```

`BE32` is a 4-byte big-endian unsigned integer. The outer `AD` is application-supplied. The full result is passed as the `aad` parameter to AES-256-GCM.

### 5.6 Decrypt Algorithm

```
RatchetDecrypt(state, header, ciphertext, AD):

  // Step 1: Try skipped message keys
  key = (header.dh, header.n)
  if key in state.MKSKIPPED:
    mk = state.MKSKIPPED.pop(key)
    aad = concat_AD(AD, header)
    return AES256GCM_Decrypt(key=mk, ct=ciphertext, aad=aad)

  // Step 2: DH ratchet if sender key has changed
  if state.DHr is None or header.dh != state.DHr:
    SkipMessageKeys(state, until=header.pn)
    DHRatchet(state, header)

  // Step 3: Skip within current receiving chain
  SkipMessageKeys(state, until=header.n)

  // Step 4: Decrypt
  (state.CKr, mk) = KDF_CK(state.CKr)
  state.Nr += 1
  aad = concat_AD(AD, header)
  return AES256GCM_Decrypt(key=mk, ct=ciphertext, aad=aad)
```

### 5.7 DH Ratchet Step

```
DHRatchet(state, header):
  state.PN = state.Ns
  state.Ns = 0
  state.Nr = 0
  state.DHr = header.dh

  // Derive receiving chain key using current DHs
  (state.RK, state.CKr) = KDF_RK(state.RK, X25519(state.DHs.priv, state.DHr))

  // Generate new DH keypair and derive sending chain key
  state.DHs = X25519_generate()
  (state.RK, state.CKs) = KDF_RK(state.RK, X25519(state.DHs.priv, state.DHr))
```

Each DH ratchet step advances the root key twice: once to derive the receiving chain, once to derive the sending chain. Both advances use the same remote key (`header.dh`) but different local private keys (old vs. newly generated DHs).

### 5.8 Skipped Message Key Handling

```
SkipMessageKeys(state, until):
  if state.Nr + MAX_SKIP < until:
    raise TooManySkippedMessages
  while state.Nr < until and state.CKr is not None:
    (state.CKr, mk) = KDF_CK(state.CKr)
    state.MKSKIPPED[(state.DHr, state.Nr)] = mk
    state.Nr += 1
```

`MAX_SKIP = 1000`. This bounds the number of message keys stored simultaneously. If more than 1000 messages arrive out of order or are lost, the session raises an error and must be re-established.

The `MKSKIPPED` map is keyed by `(dh_pub_bytes, message_number)`. Keys are removed from the map when successfully used for decryption. There is no TTL on skipped keys in the current implementation; a future version should expire skipped keys after a configurable window.

### 5.9 Message Header Format

```
Header (40 bytes, big-endian):
  dh   [32 bytes]  sender's current ratchet public key (X25519)
  pn   [4 bytes]   uint32, number of messages in previous sending chain
  n    [4 bytes]   uint32, message number in current sending chain
```

The header is authenticated as part of the AEAD associated data (see Section 5.5). It is transmitted in plaintext within the sealed sender inner payload. Header encryption (Signal spec Section 3.8) is a planned future feature.

### 5.10 Security Properties Summary

| Property | Mechanism |
|---|---|
| Forward secrecy | Chain keys advanced via HMAC one-way function; old values overwritten |
| Break-in recovery | DH ratchet introduces fresh entropy on each reply |
| Message key independence | Each message uses a unique AES-256-GCM key |
| Header integrity | Header serialized into AEAD associated data |
| Out-of-order delivery | MKSKIPPED stores up to 1000 pre-derived message keys |

---

## 6. Sealed Sender

Sealed sender hides sender identity from the relay. The relay can route a message to its destination but cannot determine who sent it.

### 6.1 Design

The sealed sender envelope has two layers:

```
Outer envelope (visible to relay):
  recipient_key_hint    8 bytes hex (first 8 bytes of recipient IK DH pub)
  sealed_blob           opaque bytes (ECIES-encrypted, described below)

Inner payload (inside sealed_blob, visible only to recipient):
  sender_certificate    authenticates the sender to the recipient
  ratchet_header        the Double Ratchet message header
  ciphertext            the Double Ratchet encrypted message body
```

The `recipient_key_hint` is a 64-bit prefix of the recipient's IK DH public key, sufficient for relay routing. The sender's identity does not appear anywhere outside the `sealed_blob`.

### 6.2 Sender Certificate

A short-lived credential that authenticates the sender to the recipient only. Never visible to the relay.

```
SenderCertificate:
  sender_ik_dh_pub   [32 bytes]  sender's X25519 IK DH public key
  sender_sign_pub    [32 bytes]  sender's Ed25519 signing public key
  expires_at         [8 bytes]   uint64 big-endian Unix timestamp (seconds)
  sig_len            [4 bytes]   uint32 big-endian, always 64
  signature          [64 bytes]  Ed25519 signature (see below)

Signed body = sender_ik_dh_pub || sender_sign_pub || expires_at
Signature   = Ed25519_sign(sender.ik_sign_priv, signed_body)
```

Certificate TTL is 24 hours (`CERT_TTL_SECONDS = 86400`). The recipient verifies:
1. The current time is before `expires_at`.
2. The Ed25519 signature over the signed body is valid under `sender_sign_pub`.

### 6.3 ECIES Encryption of the Sealed Blob

```
ECIES_Encrypt(recipient_ik_dh_pub, plaintext):

  1. EPH = X25519_generate()
  2. shared  = X25519(EPH.priv, recipient_ik_dh_pub)
  3. enc_key = HKDF-SHA256(
         salt=EPH.pub,
         ikm=shared,
         info=b"ShadowSealedSender",
         length=32
     )
  4. nonce = random(12)
  5. ct    = AES256GCM_Encrypt(key=enc_key, nonce=nonce, pt=plaintext, aad=None)

  Output: EPH.pub (32) || nonce (12) || ct || tag (16)
```

```
ECIES_Decrypt(recipient_ik_dh_priv, blob):

  EPH_pub = blob[0:32]
  nonce   = blob[32:44]
  ct      = blob[44:]

  shared  = X25519(recipient_ik_dh_priv, EPH_pub)
  enc_key = HKDF-SHA256(salt=EPH_pub, ikm=shared,
                        info=b"ShadowSealedSender", length=32)
  return AES256GCM_Decrypt(key=enc_key, nonce=nonce, ct=ct, aad=None)
```

Using the ephemeral public key as the HKDF salt binds the derived encryption key to the specific ephemeral key, preventing reuse of a derived key across different ephemeral keys.

### 6.4 Inner Payload Serialization

```
inner = cert_len (4) || cert_bytes
     || hdr_len  (4) || hdr_bytes
     || ct_len   (4) || ct_bytes
```

All lengths are uint32 big-endian. `cert_bytes` is the serialized `SenderCertificate`. `hdr_bytes` is the serialized Double Ratchet header (40 bytes). `ct_bytes` is the AES-256-GCM ciphertext from the Double Ratchet encrypt step (nonce prepended).

### 6.5 Seal and Unseal Algorithms

**Seal (sender):**

```
SealMessage(sender, recipient_ik_pub, ratchet_state, plaintext, AD):
  cert          = IssueCertificate(sender)
  (header, ct)  = RatchetEncrypt(ratchet_state, plaintext, AD)
  inner         = PackInner(cert, header, ct)
  sealed_blob   = ECIES_Encrypt(recipient_ik_pub, inner)
  hint          = recipient_ik_pub[0:8].hex()
  return SealedEnvelope(recipient_key_hint=hint, sealed_blob=sealed_blob)
```

**Unseal (recipient):**

```
UnsealMessage(recipient, ratchet_state, envelope, AD):
  inner            = ECIES_Decrypt(recipient.ik_dh_priv, envelope.sealed_blob)
  (cert, hdr, ct)  = UnpackInner(inner)
  cert.verify()    // raises on expired or bad signature
  plaintext        = RatchetDecrypt(ratchet_state, hdr, ct, AD)
  return (plaintext, cert)
```

### 6.6 Nostr Transport Binding

Shadow messages are published as Nostr kind-14 events (NIP-17 sealed DMs). The sealed envelope is base64-encoded as the event `content` field.

```json
{
  "kind": 14,
  "pubkey": "<sender Nostr x-only secp256k1 pubkey hex>",
  "created_at": 1710000000,
  "tags": [["p", "<recipient Nostr x-only pubkey hex>"]],
  "content": "<base64(SealedEnvelope.serialize())>",
  "id": "<sha256 of canonical serialization>",
  "sig": "<BIP340 Schnorr signature>"
}
```

The Nostr keypair is entirely separate from the Shadow identity keypair. It is used only for Nostr relay-level event authentication (preventing event spoofing at the relay). A Nostr relay operator can observe the Nostr pubkeys of sender and recipient, but cannot link them to Shadow cryptographic identity keys.

---

## 7. Message Wire Formats

All multi-byte integers are big-endian unless otherwise noted.

### 7.1 Double Ratchet Header (40 bytes)

```
Offset  Size    Field
     0    32    dh        sender's current ratchet public key (X25519)
    32     4    pn        uint32, messages sent in previous chain
    36     4    n         uint32, message number in current chain
Total: 40 bytes
```

### 7.2 AEAD Ciphertext (per message)

```
Offset  Size      Field
     0    12    nonce     random AES-GCM nonce
    12  var     ct+tag    AES-256-GCM ciphertext with appended 16-byte auth tag
Total: 12 + len(plaintext) + 16 bytes
```

### 7.3 X3DH Initial Message

```
Offset   Size     Field
     0     32     ik_pub        Alice's IK DH public key
    32     32     ek_pub        Alice's ephemeral public key
    64      4     spk_id        uint32, Bob's SPK identifier
    68      1     has_opk       0x01 if OPK used, 0x00 otherwise
    69      4     opk_id        uint32, Bob's OPK id (0xFFFFFFFF if none)
    73      4     hdr_len       uint32, length of header_bytes
    77   h      header_bytes  serialized ratchet header (normally 40 bytes)
  77+h      4     ct_len        uint32, length of ciphertext
  81+h   ct_len   ciphertext    AEAD ciphertext of initial message
Minimum total: 81 + 40 + 12 + 16 = 149 bytes
```

### 7.4 Sender Certificate (140 bytes fixed)

```
Offset  Size   Field
     0    32   sender_ik_dh_pub   X25519 public key
    32    32   sender_sign_pub    Ed25519 verifying key
    64     8   expires_at         uint64 Unix timestamp (seconds)
    72     4   sig_len            uint32, always 64
    76    64   signature          Ed25519 signature
Total: 140 bytes
```

### 7.5 Sealed Sender Inner Payload

```
Offset             Size      Field
              0      4       cert_len      uint32 (normally 140)
              4  cert_len    cert_bytes    serialized SenderCertificate
  4+cert_len         4       hdr_len       uint32 (normally 40)
  8+cert_len    hdr_len      hdr_bytes     serialized Header
  8+cert+hdr         4       ct_len        uint32
 12+cert+hdr   ct_len        ct_bytes      Double Ratchet ciphertext
```

### 7.6 ECIES Sealed Blob

```
Offset  Size      Field
     0    32      eph_pub     ephemeral X25519 public key
    32    12      nonce       AES-GCM nonce
    44  var       ct+tag      AES-256-GCM ciphertext of inner payload, tag appended
Total: 44 + len(inner) + 16 bytes
```

### 7.7 Sealed Envelope (outer, relay-visible)

```
Offset     Size      Field
        0      4     hint_len    uint32 (always 8)
        4      8     hint_bytes  first 8 bytes of recipient IK DH pub
       12      4     blob_len    uint32
       16  blob_len  sealed_blob ECIES-encrypted inner payload
Total: 16 + blob_len bytes
```

---

## 8. Key Rotation Policies

### 8.1 Signed Pre-Key (SPK)

**Rotation frequency:** Weekly (7 days, target interval).

**Procedure:**
1. Generate a new X25519 SPK keypair.
2. Sign the new SPK public key with `ik_sign_priv`.
3. Publish the updated PreKeyBundle to the prekey server.
4. Retain the old SPK private key for a 48-hour grace period to decrypt in-flight X3DH messages that used the old SPK.
5. Delete the old SPK private key after the grace period.

Frequent rotation limits the window during which a compromised SPK can be used to attack new sessions.

### 8.2 One-Time Pre-Keys (OPK)

**Replenishment trigger:** When the OPK pool on the server falls below a threshold (default: 10 keys), the device generates and publishes a new batch (default: 100 keys).

**Deletion:** The server deletes each OPK from its pool on fetch. The device deletes the OPK private key after X3DH receive completes. If deletion fails (e.g., process crash), the OPK must be deleted on next startup before accepting any new sessions.

**Exhaustion:** If no OPKs remain, X3DH proceeds without DH4. The Double Ratchet provides break-in recovery immediately after the first reply from Bob.

### 8.3 Ratchet DH Keys

The ratchet generates a new DH keypair on every DH ratchet step. Old private keys are deleted immediately. This is managed automatically by `DHRatchet` and requires no explicit application policy.

### 8.4 Identity Key (IK)

No automatic rotation. The identity key is the persistent identity. To change identity, the user must:
1. Generate a new `DeviceIdentity`.
2. Notify contacts out-of-band (re-establish sessions with the new key).
3. Destroy the old identity key material securely.

### 8.5 Sender Certificates

Sender certificates expire 24 hours after issuance. A new certificate is issued for each `SealMessage` call in the current implementation. Future versions may cache the certificate for its TTL.

---

## 9. Session Initialization and Teardown

### 9.1 Session Establishment

```
Preconditions:
  - Alice has fetched and verified Bob's PreKeyBundle.
  - Bob's SPK signature is valid.

Alice:
  1. (init_msg, alice_state) = x3dh_send(alice_identity, bob_bundle, initial_pt, AD)
  2. Store alice_state keyed by Bob's ik_dh_pub.
  3. Transmit init_msg via transport.

Bob:
  1. Receive InitialMessage.
  2. Look up spk by InitialMessage.spk_id.
  3. Look up opk by InitialMessage.opk_id (or None).
  4. (plaintext, bob_state) = x3dh_receive(bob_identity, spk, opk, init_msg, AD)
  5. Store bob_state keyed by Alice's ik_dh_pub (from InitialMessage.ik_pub).
  6. Delete OPK private key.
```

### 9.2 Ongoing Messaging

After session establishment, all subsequent messages use the Double Ratchet via Sealed Sender:

```
Sender:
  envelope = SealMessage(sender_identity, recipient_ik_pub,
                         ratchet_state, plaintext, AD)
  Transmit envelope via transport.

Recipient:
  (plaintext, cert) = UnsealMessage(recipient_identity,
                                    ratchet_state, envelope, AD)
  Verify cert.sender_ik_dh_pub == expected_sender_ik_pub.
```

### 9.3 Session Storage

The ratchet state must be persisted between messages. In the current CLI implementation, state is serialized to JSON and stored at `~/.shadow/sessions/<contact_ik_pub_hex>.json`. This file is not encrypted at rest in the current version. Future versions will encrypt the session store with a device-level key derived from a user passphrase via Argon2id.

### 9.4 Session Teardown

There is no explicit session teardown message in the current protocol. A session is considered closed when the ratchet state is deleted. To start a fresh session, Alice must perform a new X3DH with a fresh PreKeyBundle from Bob, deriving a different SK.

### 9.5 Duplicate Session Prevention

If Alice sends two X3DH InitialMessages (e.g., due to a retry), both carry different EK values and therefore derive different SK values, resulting in two independent ratchet sessions. Implementations should surface duplicate session establishment to the user for review.

---

## 10. Out-of-Order Delivery

### 10.1 Within-Chain Out-of-Order

If message N arrives before messages N-1, N-2, ..., the recipient calls `SkipMessageKeys(state, until=N)`, pre-deriving and storing the intermediate keys in `MKSKIPPED`. When those messages later arrive, their keys are found in the map.

### 10.2 Cross-Chain Out-of-Order

If the recipient has advanced to a new receiving chain before receiving all messages from the previous chain, `SkipMessageKeys(state, until=header.pn)` is called before the DH step. The `pn` field in the message header tells the recipient how many messages were sent on the previous chain.

### 10.3 Algorithm

```
RatchetDecrypt full path:

  // Check skipped keys first
  if (header.dh, header.n) in MKSKIPPED:
    mk = MKSKIPPED.pop((header.dh, header.n))
    return AEAD_decrypt(mk, ct, concat_AD(AD, header))

  // New DH key -> ratchet step
  if header.dh != state.DHr:
    SkipMessageKeys(state, until=header.pn)   // save tail of old receive chain
    DHRatchet(state, header)

  // In-order skip within current receive chain
  SkipMessageKeys(state, until=header.n)

  // Decrypt the current message
  (state.CKr, mk) = KDF_CK(state.CKr)
  state.Nr += 1
  return AEAD_decrypt(mk, ct, concat_AD(AD, header))
```

### 10.4 Limits

- `MAX_SKIP = 1000`: Attempting to store more than 1000 skipped keys in one step raises `TooManySkippedMessages`. The session must be re-established.
- No TTL on skipped keys: A delayed message will decrypt as long as the key remains in `MKSKIPPED`. A future version will add configurable TTL.

---

## 11. Forward Secrecy and Break-in Recovery

### 11.1 Forward Secrecy

**Claim:** If an adversary obtains the full ratchet state at time T, they cannot decrypt any message sent before T.

**Proof sketch:** Messages before T were encrypted with message keys `mk` derived from chain keys that have since been advanced. The chain key ratchet is a one-way function (HMAC-SHA256): given `CK_n`, an adversary can compute `CK_{n+k}` for k >= 0 but cannot invert to `CK_{n-1}`. The root key ratchet is similarly one-way via HKDF: given `RK_n`, computing `RK_{n-1}` requires the DH output used in that ratchet step, which requires a private key that has been deleted.

**Caveat:** Skipped message keys in `MKSKIPPED` are not subject to forward secrecy. A key for a skipped message remains in the map until consumed. If state is captured before a skipped message key is consumed, that specific message can be decrypted.

### 11.2 Break-in Recovery (Post-Compromise Security)

**Claim:** If an adversary obtains the full ratchet state at time T, there exists a time T' > T such that the adversary cannot decrypt messages sent at or after T'.

**Proof sketch:** The adversary holds the state at T, including `DHs`, `DHr`, `RK`, `CKs`, `CKr`. At each DH ratchet step after T:

1. The local party generates a new `DHs` keypair. The adversary does not know `DHs.priv`.
2. The new `RK` is derived from `HKDF(old_RK, X25519(new_DHs.priv, DHr))`. Without `new_DHs.priv`, the adversary cannot compute the new `RK`.
3. All chain keys and message keys derived from the new `RK` are unknown to the adversary.

Recovery requires at most one round-trip after compromise: every reply from the other party includes a new `DHs.pub` in the header, triggering a DH step at the receiver.

### 11.3 OPK Forward Secrecy

With an OPK present during X3DH, SK includes `DH4 = X25519(EK_A, OPK_B)`. An adversary who later compromises `bob.ik_dh_priv` and `spk.priv` cannot compute SK without `opk.priv`, which is deleted after X3DH receive. Sessions established with an OPK are therefore forward-secret with respect to long-term key compromise.

Without an OPK, SK is computed from DH1, DH2, DH3 only. Compromise of `spk.priv` and `alice.ik_dh_priv` is sufficient to compute SK for those sessions. This is a documented trade-off in the Signal X3DH specification.

---

## 12. References

1. Marlinspike, M. and Perrin, T. (2016). **The Double Ratchet Algorithm.** Signal Messenger. https://signal.org/docs/specifications/doubleratchet/

2. Marlinspike, M. and Perrin, T. (2016). **The X3DH Key Agreement Protocol.** Signal Messenger. https://signal.org/docs/specifications/x3dh/

3. Krawczyk, H. and Eronen, P. (2010). **HMAC-based Extract-and-Expand Key Derivation Function (HKDF).** RFC 5869. https://www.rfc-editor.org/rfc/rfc5869

4. Bernstein, D. J. (2006). **Curve25519: new Diffie-Hellman speed records.** PKC 2006. https://cr.yp.to/ecdh/curve25519-20060209.pdf

5. Langley, A., Hamburg, M., and Turner, S. (2016). **Elliptic Curves for Security.** RFC 7748. https://www.rfc-editor.org/rfc/rfc7748

6. Josefsson, S. and Liusvaara, I. (2017). **Edwards-Curve Digital Signature Algorithm (EdDSA).** RFC 8032. https://www.rfc-editor.org/rfc/rfc8032

7. Wuille, P., Nick, J., and Ruffing, T. (2020). **Schnorr Signatures for secp256k1.** BIP 340. https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

8. Dworkin, M. (2007). **NIST Special Publication 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC.**

9. Cohn-Gordon, K., Cremers, C., Dowling, B., Garratt, L., and Stebila, D. (2016). **A Formal Security Analysis of the Signal Messaging Protocol.** EuroS&P 2017.

10. fiatjaf et al. **Nostr Protocol.** https://github.com/nostr-protocol/nostr
